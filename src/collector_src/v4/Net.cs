// Live network state, written in the SAME shape v3 produced, but without PowerShell.
//
// Why this file exists: v3 built live\network\netstat.csv and dns_cache.csv with
// Get-NetTCPConnection / Get-DnsClientCache. The bot routes live/*.csv into the
// fb_live_network family, so changing those to plain text output (as a first native draft did)
// would have quietly stopped structured connection data from ever reaching the database.
//
// Connections therefore come straight from iphlpapi - locale-independent, no shell involved,
// and it gives UDP and the owning PID too. netstat.exe output would have had to be parsed, and
// on a Russian or Ukrainian Windows its headers are translated.

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

static class Net
{
    [DllImport("iphlpapi.dll", SetLastError = true)]
    static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order,
                                           int af, int cls, int reserved);
    [DllImport("iphlpapi.dll", SetLastError = true)]
    static extern uint GetExtendedUdpTable(IntPtr table, ref int size, bool order,
                                           int af, int cls, int reserved);

    const int AF_INET = 2, AF_INET6 = 23;
    const int TCP_TABLE_OWNER_PID_ALL = 5;
    const int UDP_TABLE_OWNER_PID = 1;

    static readonly string[] TcpState = { "", "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD",
        "ESTABLISHED", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "LAST_ACK",
        "TIME_WAIT", "DELETE_TCB" };

    [StructLayout(LayoutKind.Sequential)]
    struct TcpRow4 { public uint state, local, localPort, remote, remotePort, pid; }

    [StructLayout(LayoutKind.Sequential)]
    struct TcpRow6
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] local;
        public uint localScope, localPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] remote;
        public uint remoteScope, remotePort, state, pid;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct UdpRow4 { public uint local, localPort, pid; }

    [StructLayout(LayoutKind.Sequential)]
    struct UdpRow6
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] local;
        public uint localScope, localPort, pid;
    }

    /// <summary>Ports arrive in network byte order inside a 4-byte field.</summary>
    static int Port(uint raw)
    {
        return ((int)(raw & 0xFF) << 8) | (int)((raw >> 8) & 0xFF);
    }

    static string Ip4(uint addr) { return new IPAddress(BitConverter.GetBytes(addr)).ToString(); }
    static string Ip6(byte[] b, uint scope)
    {
        try { return new IPAddress(b, scope).ToString(); } catch { return "::"; }
    }

    public static int WriteConnectionsCsv(string path, Dictionary<int, string> pidNames)
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("Protocol,LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,ProcessName");
        int n = 0;
        n += Tcp(sb, AF_INET, pidNames);
        n += Tcp(sb, AF_INET6, pidNames);
        n += Udp(sb, AF_INET, pidNames);
        n += Udp(sb, AF_INET6, pidNames);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false));
        }
        catch { }
        return n;
    }

    static int Tcp(StringBuilder sb, int af, Dictionary<int, string> names)
    {
        IntPtr buf = IntPtr.Zero;
        int size = 0, n = 0;
        try
        {
            GetExtendedTcpTable(IntPtr.Zero, ref size, true, af, TCP_TABLE_OWNER_PID_ALL, 0);
            if (size <= 0) return 0;
            buf = Marshal.AllocHGlobal(size);
            if (GetExtendedTcpTable(buf, ref size, true, af, TCP_TABLE_OWNER_PID_ALL, 0) != 0) return 0;

            int count = Marshal.ReadInt32(buf);
            IntPtr p = new IntPtr(buf.ToInt64() + 4);
            int stride = af == AF_INET ? Marshal.SizeOf(typeof(TcpRow4)) : Marshal.SizeOf(typeof(TcpRow6));
            for (int i = 0; i < count; i++)
            {
                string la, ra, st; int lp, rp, pid;
                if (af == AF_INET)
                {
                    TcpRow4 r = (TcpRow4)Marshal.PtrToStructure(p, typeof(TcpRow4));
                    la = Ip4(r.local); ra = Ip4(r.remote);
                    lp = Port(r.localPort); rp = Port(r.remotePort);
                    st = r.state < TcpState.Length ? TcpState[r.state] : r.state.ToString();
                    pid = (int)r.pid;
                }
                else
                {
                    TcpRow6 r = (TcpRow6)Marshal.PtrToStructure(p, typeof(TcpRow6));
                    la = Ip6(r.local, r.localScope); ra = Ip6(r.remote, r.remoteScope);
                    lp = Port(r.localPort); rp = Port(r.remotePort);
                    st = r.state < TcpState.Length ? TcpState[r.state] : r.state.ToString();
                    pid = (int)r.pid;
                }
                sb.AppendLine("TCP," + la + "," + lp + "," + ra + "," + rp + "," + st + ","
                              + pid + "," + Env.Csv(Name(names, pid)));
                p = new IntPtr(p.ToInt64() + stride);
                n++;
            }
        }
        catch { }
        finally { if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf); }
        return n;
    }

    static int Udp(StringBuilder sb, int af, Dictionary<int, string> names)
    {
        IntPtr buf = IntPtr.Zero;
        int size = 0, n = 0;
        try
        {
            GetExtendedUdpTable(IntPtr.Zero, ref size, true, af, UDP_TABLE_OWNER_PID, 0);
            if (size <= 0) return 0;
            buf = Marshal.AllocHGlobal(size);
            if (GetExtendedUdpTable(buf, ref size, true, af, UDP_TABLE_OWNER_PID, 0) != 0) return 0;

            int count = Marshal.ReadInt32(buf);
            IntPtr p = new IntPtr(buf.ToInt64() + 4);
            int stride = af == AF_INET ? Marshal.SizeOf(typeof(UdpRow4)) : Marshal.SizeOf(typeof(UdpRow6));
            for (int i = 0; i < count; i++)
            {
                string la; int lp, pid;
                if (af == AF_INET)
                {
                    UdpRow4 r = (UdpRow4)Marshal.PtrToStructure(p, typeof(UdpRow4));
                    la = Ip4(r.local); lp = Port(r.localPort); pid = (int)r.pid;
                }
                else
                {
                    UdpRow6 r = (UdpRow6)Marshal.PtrToStructure(p, typeof(UdpRow6));
                    la = Ip6(r.local, r.localScope); lp = Port(r.localPort); pid = (int)r.pid;
                }
                sb.AppendLine("UDP," + la + "," + lp + ",,,," + pid + "," + Env.Csv(Name(names, pid)));
                p = new IntPtr(p.ToInt64() + stride);
                n++;
            }
        }
        catch { }
        finally { if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf); }
        return n;
    }

    static string Name(Dictionary<int, string> names, int pid)
    {
        string s;
        return (names != null && names.TryGetValue(pid, out s)) ? s : "";
    }

    public static Dictionary<int, string> ProcessNames()
    {
        Dictionary<int, string> d = new Dictionary<int, string>();
        try
        {
            foreach (System.Diagnostics.Process p in System.Diagnostics.Process.GetProcesses())
                try { d[p.Id] = p.ProcessName; } catch { }
        }
        catch { }
        return d;
    }

    /// <summary>
    /// DNS cache in v3's CSV shape. Uses an INLINE PowerShell command, not a script file:
    /// ExecutionPolicy governs files, so a one-liner still runs on a machine where every .ps1
    /// is refused. Falls back to ipconfig text only if PowerShell is missing altogether.
    /// </summary>
    public static bool WriteDnsCache(string csvPath, string txtFallbackPath)
    {
        string ps = Env.PsExe();
        if (ps != null)
        {
            string cmd = "-NoProfile -NonInteractive -Command \"Get-DnsClientCache | "
                       + "Select-Object Entry,Name,Type,Status,Data,TimeToLive | "
                       + "Export-Csv -NoTypeInformation -Encoding UTF8 '" + csvPath + "'\"";
            string o;
            Env.TryRun(ps, cmd, null, out o, 60000);
            if (File.Exists(csvPath) && new FileInfo(csvPath).Length > 0) return true;
        }
        string sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
        string outp;
        if (Env.TryRun(Path.Combine(sys, "ipconfig.exe"), "/displaydns", null, out outp, 60000)
            && outp != null)
        {
            try { File.WriteAllText(txtFallbackPath, outp, new UTF8Encoding(false)); } catch { }
        }
        return false;
    }
}
