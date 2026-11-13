// --serve: llama-swap on 127.0.0.1:<SwapPort> (restarted if it dies) + the agent port for the VM.
// The proxy is plain TCP + HTTP/1.1 (no http.sys URL reservation, so it also runs without admin rights):
// one request per connection, the answer is streamed back chunked (SSE token streams pass through as
// they come).
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace DfirVao
{
    public static partial class Agent
    {
        static int active, waiting, served, refused;
        static SemaphoreSlim slots;
        static DateTime started = DateTime.UtcNow;
        static Process swap;
        static string serveLog;

        static void SLog(string m)
        {
            var line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " " + m;
            Console.WriteLine(line);
            try { lock (typeof(Agent)) File.AppendAllText(serveLog, line + "\r\n"); } catch { }
        }

        public static int Serve()
        {
            Directory.CreateDirectory(Path.Combine(Home, "logs"));
            serveLog = Path.Combine(Home, "logs", "agent.log");
            if (string.IsNullOrEmpty(S.Token)) { S.Token = NewToken(); SaveSettings(); }
            slots = new SemaphoreSlim(Math.Max(1, S.Parallel));
            if (S.Profile == "large") ClockFloor();
            new Thread(SwapKeeper) { IsBackground = true }.Start();
            var l = new TcpListener(IPAddress.Any, S.Port);
            l.Start(64);
            SLog("agent " + Version + " on 0.0.0.0:" + S.Port + " -> llama-swap 127.0.0.1:" + S.SwapPort + ", parallel " + S.Parallel);
            while (true)
            {
                var c = l.AcceptTcpClient();
                ThreadPool.QueueUserWorkItem(delegate { Handle(c); });
            }
        }

        // big-120b splits layers over every card; without a clock floor each card idles between its turns
        // (6-7 tok/s instead of 65 on 6x RTX 4080 SUPER). Needs admin/SYSTEM; harmless otherwise.
        static void ClockFloor()
        {
            foreach (var g in Gpus())
            {
                string o;
                if (Run("nvidia-smi", "-i " + g.Index + " --query-supported-clocks=memory,graphics --format=csv,noheader,nounits", out o, 20000) != 0) continue;
                var top = o.Split('\n').Select(x => x.Split(',')).Where(p => p.Length == 2)
                    .Select(p => new[] { int.Parse(p[0].Trim()), int.Parse(p[1].Trim()) })
                    .OrderByDescending(p => p[0]).ThenByDescending(p => p[1]).FirstOrDefault();
                if (top == null) continue;
                Run("nvidia-smi", "-i " + g.Index + " -lgc " + Math.Min(1500, top[1]) + "," + top[1], out o, 20000);
                Run("nvidia-smi", "-i " + g.Index + " -lmc " + top[0] + "," + top[0], out o, 20000);
            }
        }

        static void SwapKeeper()
        {
            var exe = Path.Combine(Home, "swap", "llama-swap.exe");
            var cfg = Path.Combine(Home, "config.yaml");
            while (true)
            {
                if (!File.Exists(exe) || !File.Exists(cfg)) { SLog("llama-swap or config.yaml missing: run --install"); Thread.Sleep(30000); continue; }
                var psi = new ProcessStartInfo(exe, "-config \"" + cfg + "\" -listen 127.0.0.1:" + S.SwapPort + " -watch-config")
                { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
                var log = Path.Combine(Home, "logs", "llama-swap.log");
                try
                {
                    swap = Process.Start(psi);
                    SLog("llama-swap started pid " + swap.Id);
                    DataReceivedEventHandler h = delegate(object s, DataReceivedEventArgs e) { if (e.Data != null) try { lock (log) File.AppendAllText(log, e.Data + "\r\n"); } catch { } };
                    swap.OutputDataReceived += h; swap.ErrorDataReceived += h;
                    swap.BeginOutputReadLine(); swap.BeginErrorReadLine();
                    swap.WaitForExit();
                    SLog("llama-swap exited " + swap.ExitCode + ", restarting in 5 s");
                }
                catch (Exception e) { SLog("llama-swap: " + e.Message); }
                Thread.Sleep(5000);
            }
        }

        // ---------------------------------------------------------------- HTTP
        class Req { public string Method, Path, Version; public List<KeyValuePair<string, string>> H = new List<KeyValuePair<string, string>>(); public byte[] Body = new byte[0];
            public string Get(string k) { foreach (var p in H) if (string.Equals(p.Key, k, StringComparison.OrdinalIgnoreCase)) return p.Value; return null; } }

        static string ReadLine(Stream s)
        {
            var b = new List<byte>();
            while (true)
            {
                int c = s.ReadByte();
                if (c < 0) return b.Count == 0 ? null : Encoding.ASCII.GetString(b.ToArray());
                if (c == '\n') break;
                if (c != '\r') b.Add((byte)c);
                if (b.Count > 16384) throw new IOException("header line too long");
            }
            return Encoding.ASCII.GetString(b.ToArray());
        }
        static void ReadExact(Stream s, byte[] buf, int off, int n)
        {
            while (n > 0) { int r = s.Read(buf, off, n); if (r <= 0) throw new IOException("short body"); off += r; n -= r; }
        }
        static Req ReadReq(Stream s)
        {
            var first = ReadLine(s);
            if (string.IsNullOrEmpty(first)) return null;
            var p = first.Split(' ');
            if (p.Length < 3) throw new IOException("bad request line");
            var r = new Req { Method = p[0], Path = p[1], Version = p[2] };
            for (int n = 0; ; n++)
            {
                var l = ReadLine(s);
                if (string.IsNullOrEmpty(l)) break;
                if (n > 200) throw new IOException("too many headers");
                int i = l.IndexOf(':');
                if (i > 0) r.H.Add(new KeyValuePair<string, string>(l.Substring(0, i).Trim(), l.Substring(i + 1).Trim()));
            }
            const int Max = 256 * 1024 * 1024;
            var cl = r.Get("Content-Length");
            if ((r.Get("Transfer-Encoding") ?? "").ToLowerInvariant().Contains("chunked"))
            {
                var ms = new MemoryStream();
                while (true)
                {
                    var sz = Convert.ToInt32((ReadLine(s) ?? "0").Split(';')[0].Trim(), 16);
                    if (sz == 0) { while (!string.IsNullOrEmpty(ReadLine(s))) { } break; }
                    if (ms.Length + sz > Max) throw new IOException("body too big");
                    var b = new byte[sz]; ReadExact(s, b, 0, sz); ms.Write(b, 0, sz); ReadLine(s);
                }
                r.Body = ms.ToArray();
            }
            else if (cl != null)
            {
                long n = long.Parse(cl);
                if (n > Max) throw new IOException("body too big");
                r.Body = new byte[n]; ReadExact(s, r.Body, 0, (int)n);
            }
            if (r.Get("Expect") != null && r.Get("Expect").ToLowerInvariant() == "100-continue") { }
            return r;
        }
        static void Reply(Stream s, int code, string reason, string json)
        {
            var b = Encoding.UTF8.GetBytes(json);
            var h = "HTTP/1.1 " + code + " " + reason + "\r\nContent-Type: application/json\r\nContent-Length: " + b.Length + "\r\nConnection: close\r\n\r\n";
            var hb = Encoding.ASCII.GetBytes(h);
            s.Write(hb, 0, hb.Length); s.Write(b, 0, b.Length); s.Flush();
        }
        static bool SameToken(string got)
        {
            if (string.IsNullOrEmpty(S.Token) || got == null) return false;
            var a = Encoding.UTF8.GetBytes(got); var b = Encoding.UTF8.GetBytes(S.Token);
            int diff = a.Length ^ b.Length;
            for (int i = 0; i < Math.Min(a.Length, b.Length); i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }
        static bool Authorized(Req r)
        {
            var a = r.Get("Authorization");
            if (a != null && a.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) && SameToken(a.Substring(7).Trim())) return true;
            if (SameToken(r.Get("x-api-key"))) return true;
            return false;
        }

        static void Handle(TcpClient c)
        {
            var peer = "?";
            try
            {
                peer = ((IPEndPoint)c.Client.RemoteEndPoint).Address.ToString();
                c.NoDelay = true;
                using (c) using (var s = c.GetStream())
                {
                    s.ReadTimeout = 120000;
                    var r = ReadReq(s);
                    if (r == null) return;
                    var path = r.Path.Split('?')[0];
                    if (path == "/agent/hello")
                    {
                        Reply(s, 200, "OK", new JavaScriptSerializer().Serialize(new Dictionary<string, object> {
                            { "agent", "dfir-vao-host-agent" }, { "version", Version }, { "auth", "bearer" }, { "port", S.Port } }));
                        return;
                    }
                    bool local = peer == "127.0.0.1" || peer == "::1";
                    bool statusTok = path == "/agent/status" && local && r.Path.Contains("token=") && SameToken(Uri.UnescapeDataString(r.Path.Substring(r.Path.IndexOf("token=") + 6)));
                    if (!Authorized(r) && !statusTok)
                    {
                        Interlocked.Increment(ref refused);
                        SLog("401 " + peer + " " + r.Method + " " + path);
                        Reply(s, 401, "Unauthorized", "{\"error\":{\"message\":\"DFIR VAO Host Agent: token required (Authorization: Bearer ...)\",\"type\":\"auth\"}}");
                        return;
                    }
                    if (path == "/agent/status") { Reply(s, 200, "OK", StatusJson()); return; }
                    bool infer = r.Method == "POST" && path.StartsWith("/v1/");
                    if (infer)
                    {
                        Interlocked.Increment(ref waiting);
                        try { slots.Wait(); } finally { Interlocked.Decrement(ref waiting); }
                        Interlocked.Increment(ref active);
                    }
                    try { Forward(r, s); }
                    finally { if (infer) { Interlocked.Decrement(ref active); slots.Release(); Interlocked.Increment(ref served); } }
                }
            }
            catch (Exception e) { SLog("conn " + peer + ": " + e.GetType().Name + " " + e.Message); }
        }

        static readonly HashSet<string> Hop = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { "Host", "Connection", "Keep-Alive", "Authorization", "x-api-key", "Content-Length", "Transfer-Encoding", "Expect", "Proxy-Connection", "TE", "Upgrade" };

        static void Forward(Req r, Stream client)
        {
            var up = (HttpWebRequest)WebRequest.Create("http://127.0.0.1:" + S.SwapPort + r.Path);
            up.Method = r.Method; up.Timeout = 3600 * 1000; up.ReadWriteTimeout = 3600 * 1000;
            up.AllowAutoRedirect = false; up.KeepAlive = false; up.AutomaticDecompression = DecompressionMethods.None;
            foreach (var h in r.H)
            {
                if (Hop.Contains(h.Key)) continue;
                try
                {
                    switch (h.Key.ToLowerInvariant())
                    {
                        case "content-type": up.ContentType = h.Value; break;
                        case "accept": up.Accept = h.Value; break;
                        case "user-agent": up.UserAgent = h.Value; break;
                        case "referer": up.Referer = h.Value; break;
                        case "date": case "range": case "if-modified-since": break;
                        default: up.Headers[h.Key] = h.Value; break;
                    }
                }
                catch { }
            }
            if (r.Body.Length > 0 || r.Method == "POST" || r.Method == "PUT")
            {
                up.ContentLength = r.Body.Length; up.AllowWriteStreamBuffering = false;
                using (var w = up.GetRequestStream()) w.Write(r.Body, 0, r.Body.Length);
            }
            HttpWebResponse resp;
            try { resp = (HttpWebResponse)up.GetResponse(); }
            catch (WebException e)
            {
                resp = e.Response as HttpWebResponse;
                if (resp == null) { Reply(client, 502, "Bad Gateway", "{\"error\":{\"message\":\"llama-swap is not answering: " + e.Status + "\"}}"); return; }
            }
            using (resp)
            {
                var sb = new StringBuilder("HTTP/1.1 " + (int)resp.StatusCode + " " + resp.StatusDescription + "\r\n");
                foreach (string k in resp.Headers.AllKeys)
                    if (!Hop.Contains(k)) sb.Append(k + ": " + resp.Headers[k] + "\r\n");
                sb.Append("Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
                var hb = Encoding.ASCII.GetBytes(sb.ToString());
                client.Write(hb, 0, hb.Length);
                var buf = new byte[16384];
                using (var body = resp.GetResponseStream())
                {
                    int n;
                    while ((n = body.Read(buf, 0, buf.Length)) > 0)
                    {
                        var pre = Encoding.ASCII.GetBytes(n.ToString("x") + "\r\n");
                        client.Write(pre, 0, pre.Length); client.Write(buf, 0, n); client.Write(new byte[] { 13, 10 }, 0, 2);
                        client.Flush();
                    }
                }
                var end = Encoding.ASCII.GetBytes("0\r\n\r\n");
                client.Write(end, 0, end.Length); client.Flush();
            }
        }

        public static string StatusJson()
        {
            object running = null;
            try { running = new JavaScriptSerializer().DeserializeObject(Http("http://127.0.0.1:" + S.SwapPort + "/running", 5000)); } catch { }
            var gpus = Gpus().Select(g => new Dictionary<string, object> { { "index", g.Index }, { "name", g.Name }, { "mem_used_mb", g.UsedMb },
                { "mem_total_mb", g.TotalMb }, { "util", g.Util } }).ToList();
            return new JavaScriptSerializer().Serialize(new Dictionary<string, object> {
                { "agent", "dfir-vao-host-agent" }, { "version", Version }, { "port", S.Port }, { "profile", S.Profile },
                { "llama_cpp", CurrentTag() }, { "llama_swap", S.SwapTag }, { "parallel", S.Parallel },
                { "active", active }, { "waiting", waiting }, { "served", served }, { "refused", refused },
                { "uptime_s", (int)(DateTime.UtcNow - started).TotalSeconds }, { "swap_alive", swap != null && !swap.HasExited },
                { "running", running }, { "gpus", gpus } });
        }
    }
}
