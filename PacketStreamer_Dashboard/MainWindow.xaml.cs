using LiveCharts;
using LiveCharts.Wpf;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

namespace PacketStreamer_Dashboard
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct NetworkInterface
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string name;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)] public string description;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct PacketInfo
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)] public string src_ip;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)] public string dst_ip;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 10)] public string protocol;
        public ushort length;
        public ushort src_port;
        public ushort dst_port;
        public uint timestamp_sec;
        public uint timestamp_usec;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 50)] public string payload_preview;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2000)] public byte[] raw_data;
        public ushort raw_data_length;
    }

    public class PacketRecord
    {
        public string Timestamp { get; set; }
        public string SrcIP { get; set; }
        public string DstIP { get; set; }
        public string Protocol { get; set; }
        public ushort SrcPort { get; set; }
        public ushort DstPort { get; set; }
        public ushort Length { get; set; }
        public string PayloadPreview { get; set; }
        public byte[] RawData { get; set; }
        public uint TimestampSec { get; set; }
        public uint TimestampUsec { get; set; }
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void PacketCallbackDelegate(IntPtr packetPtr);

    public class ProtocolStats : INotifyPropertyChanged
    {
        public string Protocol { get; set; }
        public Brush Color { get; set; }
        private int count;
        public int Count { get => count; set { count = value; OnPropertyChanged(nameof(Count)); OnPropertyChanged(nameof(CountText)); } }
        public string CountText => $"{Count:N0} packets";
        private double percentage;
        public double Percentage { get => percentage; set { percentage = value; OnPropertyChanged(nameof(Percentage)); OnPropertyChanged(nameof(PercentageText)); } }
        public string PercentageText => $"{Percentage:F1}%";
        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged(string name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    public class IpStats : INotifyPropertyChanged
    {
        public string Rank { get; set; }
        public string IP { get; set; }
        private int count;
        public int Count { get => count; set { count = value; OnPropertyChanged(nameof(Count)); OnPropertyChanged(nameof(CountText)); } }
        public string CountText => $"{Count:N0} pkts";
        private double percentage;
        public double Percentage { get => percentage; set { percentage = value; OnPropertyChanged(nameof(Percentage)); OnPropertyChanged(nameof(PercentageText)); } }
        public string PercentageText => $"{Percentage:F1}%";
        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged(string name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    public class DetectedFile : INotifyPropertyChanged
    {
        public string Type { get; set; }
        public string Name { get; set; }
        public string SrcIP { get; set; }
        public string DstIP { get; set; }
        public ushort SrcPort { get; set; }
        public ushort DstPort { get; set; }
        public string Ports => $"{SrcPort} → {DstPort}";
        private int hitCount;
        public int HitCount { get => hitCount; set { hitCount = value; OnPropertyChanged(nameof(HitCount)); OnPropertyChanged(nameof(HitCountText)); } }
        public string HitCountText => $"{HitCount:N0} hits";
        public Brush TypeColor => Type switch { "HTTP" => new SolidColorBrush(Color.FromRgb(0, 212, 255)), "DNS" => new SolidColorBrush(Color.FromRgb(255, 170, 0)), "TLS" => new SolidColorBrush(Color.FromRgb(0, 255, 136)), _ => Brushes.Gray };
        public string TypeIcon => Type switch { "HTTP" => "🌐", "DNS" => "🔍", "TLS" => "🔒", _ => "📄" };
        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged(string name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    public class CapturedFileRecord : INotifyPropertyChanged
    {
        public string Timestamp { get; set; }
        public string SourceIP { get; set; }
        public string DestIP { get; set; }
        public string ContentType { get; set; }
        public string FileName { get; set; }
        public string FilePath { get; set; }
        public long FileSize { get; set; }
        public string FileSizeText => FileSize > 1024 ? $"{FileSize / 1024} KB" : $"{FileSize} B";
        public string FileIcon => ContentType.Contains("html") ? "🌐" : ContentType.Contains("image") ? "🖼️" : ContentType.Contains("javascript") ? "⚙️" : ContentType.Contains("css") ? "🎨" : "📄";
        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged(string name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    public partial class MainWindow : Window
    {
        const string DLL = @"PacketStreamer_Core.dll";
        [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)] public static extern int InitializeWinsock();
        [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)] public static extern void CleanupWinsock();
        [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)] public static extern int GetNetworkInterfaces([Out] NetworkInterface[] interfaces, int maxCount);
        [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)] public static extern void StopCapture();
        [DllImport(DLL, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)] public static extern void StartCapture(string deviceName, PacketCallbackDelegate callback);

        private Dictionary<string, int> protocolCounts = new Dictionary<string, int>();
        private Dictionary<string, PieSeries> protocolSeriesMap = new Dictionary<string, PieSeries>();
        private Dictionary<string, ChartValues<int>> protocolValuesMap = new Dictionary<string, ChartValues<int>>();
        private Dictionary<string, ProtocolStats> protocolStatsMap = new Dictionary<string, ProtocolStats>();
        private SeriesCollection seriesCollection = new SeriesCollection();
        private ObservableCollection<ProtocolStats> protocolStatsList = new ObservableCollection<ProtocolStats>();

        private PacketRingBuffer packetHistory;
        private int userDesiredCapacity = 10000;

        private int totalPackets = 0;
        private DateTime startTime;
        private PacketCallbackDelegate callbackDelegate;
        private Thread captureThread;
        private bool isCapturing = false;

        private Dictionary<string, Brush> protocolColors = new Dictionary<string, Brush>
        {
            { "TCP", new SolidColorBrush(Color.FromRgb(0, 212, 255)) },
            { "UDP", new SolidColorBrush(Color.FromRgb(0, 255, 136)) },
            { "ICMP", new SolidColorBrush(Color.FromRgb(255, 68, 68)) },
            { "ICMPv6", new SolidColorBrush(Color.FromRgb(255, 100, 100)) },
            { "IGMP", new SolidColorBrush(Color.FromRgb(255, 170, 0)) },
            { "GRE", new SolidColorBrush(Color.FromRgb(170, 0, 255)) },
            { "ESP", new SolidColorBrush(Color.FromRgb(255, 0, 170)) },
            { "AH", new SolidColorBrush(Color.FromRgb(0, 170, 255)) },
            { "OSPF", new SolidColorBrush(Color.FromRgb(255, 255, 0)) },
            { "SCTP", new SolidColorBrush(Color.FromRgb(0, 255, 255)) },
            { "Other", new SolidColorBrush(Color.FromRgb(150, 150, 150)) }
        };

        private ChartValues<int> ppsValues = new ChartValues<int>();
        private List<int> ppsHistory = new List<int>();
        private int packetsInCurrentSecond = 0;
        private int peakPps = 0;
        private const int MAX_TIME_POINTS = 30;

        private ChartValues<double> bpsValues = new ChartValues<double>();
        private List<double> bpsHistory = new List<double>();
        private long bytesInCurrentSecond = 0;
        private long totalBytes = 0;
        private long peakBps = 0;

        private BackgroundAnalyzer backgroundAnalyzer;
        private List<double> bpsValuesList = new List<double>(30);

        private Dictionary<string, int> srcIpCounts = new Dictionary<string, int>();
        private Dictionary<string, int> dstIpCounts = new Dictionary<string, int>();
        private Dictionary<string, IpStats> srcIpStatsMap = new Dictionary<string, IpStats>();
        private Dictionary<string, IpStats> dstIpStatsMap = new Dictionary<string, IpStats>();
        private ObservableCollection<IpStats> topSourceList = new ObservableCollection<IpStats>();
        private ObservableCollection<IpStats> topDestList = new ObservableCollection<IpStats>();
        private const int MAX_TOP_TALKERS = 20;

        private Dictionary<string, DetectedFile> detectedFilesMap = new Dictionary<string, DetectedFile>();
        private ObservableCollection<DetectedFile> detectedFilesList = new ObservableCollection<DetectedFile>();
        private ObservableCollection<CapturedFileRecord> capturedFilesList = new ObservableCollection<CapturedFileRecord>();
        private string captureFolder = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "CapturedFiles");

        public MainWindow()
        {
            InitializeComponent();
            Loaded += MainWindow_Loaded;

            if (!Directory.Exists(captureFolder)) Directory.CreateDirectory(captureFolder);

            ProtocolPieChart.DisableAnimations = true;
            ProtocolPieChart.AnimationsSpeed = TimeSpan.Zero;
            ProtocolPieChart.Hoverable = false;

            var ppsSeries = new LineSeries { Title = "Packets/sec", Values = ppsValues, PointGeometry = null, LineSmoothness = 0, StrokeThickness = 2, Fill = Brushes.Transparent, Stroke = new SolidColorBrush(Color.FromRgb(0, 255, 136)) };
            TimeSeriesChart.Series = new SeriesCollection { ppsSeries };

            var bpsSeries = new LineSeries { Title = "Bytes/sec", Values = bpsValues, PointGeometry = null, LineSmoothness = 0, StrokeThickness = 2, Fill = Brushes.Transparent, Stroke = new SolidColorBrush(Color.FromRgb(0, 212, 255)) };
            if (TimeSeriesChart2 != null) TimeSeriesChart2.Series = new SeriesCollection { bpsSeries };

            ProtocolListBox.ItemsSource = protocolStatsList;
            TopSourceList.ItemsSource = topSourceList;
            TopDestList.ItemsSource = topDestList;
            DetectedFilesList.ItemsSource = detectedFilesList;

            packetHistory = new PacketRingBuffer(userDesiredCapacity);
            backgroundAnalyzer = new BackgroundAnalyzer(AnalyzePacketForFiles, ExtractAndSaveHttpFile);
            backgroundAnalyzer.Start();
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            InitializeWinsock();
            LoadNetworkInterfaces();
        }

        private void LoadNetworkInterfaces()
        {
            NetworkInterface[] interfaces = new NetworkInterface[20];
            int count = GetNetworkInterfaces(interfaces, 20);
            if (count > 0)
            {
                for (int i = 0; i < count; i++) InterfaceComboBox.Items.Add(interfaces[i].description);
                InterfaceComboBox.SelectedIndex = 0;
            }
        }

        private void StartButton_Click(object sender, RoutedEventArgs e)
        {
            if (!isCapturing)
            {
                if (totalPackets > 0)
                {
                    var result = MessageBox.Show("Previous capture data exists.\n\nYes = Continue\nNo = Clear and start fresh\nCancel = Abort", "PacketStreamer", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
                    if (result == MessageBoxResult.Cancel) return;
                    if (result == MessageBoxResult.No) ResetAllData();
                }

                if (InterfaceComboBox.SelectedIndex < 0) { MessageBox.Show("Please select a network interface."); return; }

                NetworkInterface[] interfaces = new NetworkInterface[20];
                int count = GetNetworkInterfaces(interfaces, 20);
                string selectedDevice = interfaces[InterfaceComboBox.SelectedIndex].name;

                callbackDelegate = new PacketCallbackDelegate(OnPacketReceived);
                captureThread = new Thread(() => StartCapture(selectedDevice, callbackDelegate)) { IsBackground = true };
                captureThread.Start();

                isCapturing = true;
                if (totalPackets == 0) startTime = DateTime.Now;

                StartButton.Content = "⏹ Stop Capture";
                StartButton.Background = new SolidColorBrush(Color.FromRgb(255, 68, 68));
                InterfaceComboBox.IsEnabled = false;

                DispatcherTimer uiTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
                uiTimer.Tick += UiTimer_Tick;
                uiTimer.Start();
            }
            else
            {
                StopCapture();
                if (captureThread != null && captureThread.IsAlive) captureThread.Join(2000);
                isCapturing = false;
                StartButton.Content = "▶ Start Capture";
                StartButton.Background = new SolidColorBrush(Color.FromRgb(0, 212, 255));
                InterfaceComboBox.IsEnabled = true;
            }
        }

        // ========================================================================
        // ✅ FIX: این متد اصلاح شد تا protocolCounts را به‌روزرسانی کند
        // ========================================================================
        private void OnPacketReceived(IntPtr packetPtr)
        {
            PacketInfo packet = Marshal.PtrToStructure<PacketInfo>(packetPtr);

            System.Threading.Interlocked.Increment(ref totalPackets);
            System.Threading.Interlocked.Increment(ref packetsInCurrentSecond);
            System.Threading.Interlocked.Add(ref bytesInCurrentSecond, packet.length);
            System.Threading.Interlocked.Add(ref totalBytes, packet.length);

            // ✅ FIX: شمارش پروتکل‌ها (این بخش حذف شده بود و باعث خالی شدن داشبورد می‌شد!)
            lock (protocolCounts)
            {
                if (!protocolCounts.ContainsKey(packet.protocol)) protocolCounts[packet.protocol] = 0;
                protocolCounts[packet.protocol]++;
            }

            byte[] rawData = null;
            if (packet.raw_data_length > 0 && packet.raw_data != null)
            {
                rawData = new byte[packet.raw_data_length];
                Buffer.BlockCopy(packet.raw_data, 0, rawData, 0, packet.raw_data_length);
            }

            var record = new PacketRecord
            {
                Timestamp = DateTimeOffset.FromUnixTimeSeconds(packet.timestamp_sec).AddMilliseconds(packet.timestamp_usec / 1000).ToLocalTime().ToString("HH:mm:ss.fff"),
                SrcIP = packet.src_ip,
                DstIP = packet.dst_ip,
                Protocol = packet.protocol,
                SrcPort = packet.src_port,
                DstPort = packet.dst_port,
                Length = packet.length,
                PayloadPreview = packet.payload_preview?.Trim() ?? "",
                RawData = rawData,
                TimestampSec = packet.timestamp_sec,
                TimestampUsec = packet.timestamp_usec
            };

            packetHistory.Add(record);

            lock (srcIpCounts) { if (!srcIpCounts.TryGetValue(packet.src_ip, out int srcCount)) srcCount = 0; srcIpCounts[packet.src_ip] = srcCount + 1; }
            lock (dstIpCounts) { if (!dstIpCounts.TryGetValue(packet.dst_ip, out int dstCount)) dstCount = 0; dstIpCounts[packet.dst_ip] = dstCount + 1; }

            backgroundAnalyzer?.Enqueue(record);
        }

        private void UiTimer_Tick(object sender, EventArgs e)
        {
            TotalPacketsText.Text = $"Total Packets: {totalPackets:N0}";
            double elapsedSeconds = (DateTime.Now - startTime).TotalSeconds;
            int pps = elapsedSeconds > 0 ? (int)(totalPackets / elapsedSeconds) : 0;
            PacketsPerSecondText.Text = $"Packets/sec: {pps:N0}";

            UpdatePieChart();
            UpdateProtocolList();
            UpdatePacketList();
            UpdateTimeSeriesChart();
            UpdateTopTalkers();
            SyncDetectedFilesToUI();
        }

        private void UpdatePieChart()
        {
            lock (protocolCounts)
            {
                bool seriesChanged = false;
                foreach (var kvp in protocolCounts)
                {
                    if (!protocolSeriesMap.ContainsKey(kvp.Key))
                    {
                        var chartValues = new ChartValues<int> { kvp.Value };
                        protocolValuesMap[kvp.Key] = chartValues;
                        var newSeries = new PieSeries { Title = kvp.Key, Values = chartValues, DataLabels = true, LabelPoint = cp => $"{cp.Participation:P1}" };
                        if (protocolColors.ContainsKey(kvp.Key)) newSeries.Fill = protocolColors[kvp.Key];
                        seriesCollection.Add(newSeries);
                        protocolSeriesMap[kvp.Key] = newSeries;
                        seriesChanged = true;
                    }
                    else
                    {
                        var cv = protocolValuesMap[kvp.Key];
                        if (cv.Count > 0) cv[0] = kvp.Value;
                    }
                }
                if (seriesChanged || ProtocolPieChart.Series == null) ProtocolPieChart.Series = seriesCollection;
            }
        }

        private void UpdateProtocolList()
        {
            lock (protocolCounts)
            {
                var sorted = protocolCounts.OrderByDescending(x => x.Value).ToList();
                foreach (var kvp in sorted)
                {
                    double pct = totalPackets > 0 ? (double)kvp.Value / totalPackets * 100 : 0;
                    if (!protocolStatsMap.ContainsKey(kvp.Key))
                    {
                        var stats = new ProtocolStats { Protocol = kvp.Key, Color = protocolColors.ContainsKey(kvp.Key) ? protocolColors[kvp.Key] : Brushes.White, Count = kvp.Value, Percentage = pct };
                        protocolStatsMap[kvp.Key] = stats;
                        protocolStatsList.Add(stats);
                    }
                    else
                    {
                        protocolStatsMap[kvp.Key].Count = kvp.Value;
                        protocolStatsMap[kvp.Key].Percentage = pct;
                    }
                }
            }
        }

        private void UpdatePacketList()
        {
            bool isFiltered = !string.IsNullOrEmpty(FilterGlobal?.Text) || !string.IsNullOrEmpty(FilterSrcIp?.Text) || !string.IsNullOrEmpty(FilterDstIp?.Text) ||
                              !string.IsNullOrEmpty(FilterSrcPort?.Text) || !string.IsNullOrEmpty(FilterDstPort?.Text) || (FilterProto != null && FilterProto.SelectedIndex > 0) || !string.IsNullOrEmpty(FilterLength?.Text);

            if (!isFiltered)
            {
                var displayList = packetHistory.GetLastN(1000);
                PacketDataGrid.ItemsSource = displayList;
                if (FilterResultText != null) FilterResultText.Text = $"Buffer: {packetHistory.Count:N0} / {packetHistory.Capacity:N0}";
            }
        }

        private void UpdateTimeSeriesChart()
        {
            int currentPps = System.Threading.Interlocked.Exchange(ref packetsInCurrentSecond, 0);
            long currentBps = System.Threading.Interlocked.Exchange(ref bytesInCurrentSecond, 0);

            ppsHistory.Add(currentPps);
            bpsHistory.Add(currentBps);
            bpsValuesList.Add(currentBps);

            if (ppsHistory.Count > MAX_TIME_POINTS) ppsHistory.RemoveRange(0, ppsHistory.Count - MAX_TIME_POINTS);
            if (bpsHistory.Count > MAX_TIME_POINTS) bpsHistory.RemoveRange(0, bpsHistory.Count - MAX_TIME_POINTS);
            if (bpsValuesList.Count > MAX_TIME_POINTS) bpsValuesList.RemoveRange(0, bpsValuesList.Count - MAX_TIME_POINTS);

            ppsValues.Clear();
            foreach (var v in ppsHistory) ppsValues.Add(v);

            if (TimeSeriesChart2 != null)
            {
                bpsValues.Clear();
                foreach (var v in bpsValuesList) bpsValues.Add((double)v);
            }

            if (currentPps > peakPps) peakPps = currentPps;
            double avgPps = ppsHistory.Count > 0 ? ppsHistory.Average() : 0;
            if (currentBps > peakBps) peakBps = currentBps;
            double avgBps = bpsHistory.Count > 0 ? bpsHistory.Average() : 0;

            CurrentPpsText.Text = currentPps.ToString("N0");
            PeakPpsText.Text = peakPps.ToString("N0");
            AvgPpsText.Text = avgPps.ToString("N0");
            CurrentBpsText.Text = FormatBytes(currentBps) + "/s";
            PeakBpsText.Text = FormatBytes(peakBps) + "/s";
            AvgBpsText.Text = FormatBytes((long)avgBps) + "/s";
            TotalBytesText.Text = $"Total: {FormatBytes(totalBytes)}";
        }

        private string FormatBytes(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1048576) return $"{bytes / 1024.0:F1} KB";
            if (bytes < 1073741824L) return $"{bytes / 1048576.0:F1} MB";
            return $"{bytes / 1073741824.0:F2} GB";
        }

        private void UpdateTopTalkers()
        {
            lock (srcIpCounts)
            {
                var sorted = srcIpCounts.OrderByDescending(x => x.Value).Take(MAX_TOP_TALKERS).ToList();
                int total = srcIpCounts.Values.Sum();
                topSourceList.Clear();
                for (int i = 0; i < sorted.Count; i++)
                {
                    double pct = total > 0 ? (double)sorted[i].Value / total * 100 : 0;
                    topSourceList.Add(new IpStats { Rank = $"#{i + 1}", IP = sorted[i].Key, Count = sorted[i].Value, Percentage = pct });
                }
            }
            lock (dstIpCounts)
            {
                var sorted = dstIpCounts.OrderByDescending(x => x.Value).Take(MAX_TOP_TALKERS).ToList();
                int total = dstIpCounts.Values.Sum();
                topDestList.Clear();
                for (int i = 0; i < sorted.Count; i++)
                {
                    double pct = total > 0 ? (double)sorted[i].Value / total * 100 : 0;
                    topDestList.Add(new IpStats { Rank = $"#{i + 1}", IP = sorted[i].Key, Count = sorted[i].Value, Percentage = pct });
                }
            }
        }

        private void SyncDetectedFilesToUI()
        {
            lock (detectedFilesMap)
            {
                detectedFilesList.Clear();
                foreach (var f in detectedFilesMap.Values.OrderByDescending(x => x.HitCount)) detectedFilesList.Add(f);
                HttpCountText.Text = detectedFilesMap.Values.Count(f => f.Type == "HTTP").ToString();
                DnsCountText.Text = detectedFilesMap.Values.Count(f => f.Type == "DNS").ToString();
                TlsCountText.Text = detectedFilesMap.Values.Count(f => f.Type == "TLS").ToString();
            }
        }

        private void ApplyFilter_Click(object sender, RoutedEventArgs e)
        {
            string globalSearch = FilterGlobal.Text.Trim().ToLower();
            string srcIp = FilterSrcIp.Text.Trim().ToLower();
            string dstIp = FilterDstIp.Text.Trim().ToLower();
            string srcPortStr = FilterSrcPort.Text.Trim();
            string dstPortStr = FilterDstPort.Text.Trim();
            string proto = (FilterProto.SelectedItem as ComboBoxItem)?.Content.ToString();
            string lengthStr = FilterLength.Text.Trim();

            IEnumerable<PacketRecord> query = packetHistory.ToList();

            if (!string.IsNullOrEmpty(globalSearch))
                query = query.Where(p => p.SrcIP.ToLower().Contains(globalSearch) || p.DstIP.ToLower().Contains(globalSearch) || p.Protocol.ToLower().Contains(globalSearch) || (p.PayloadPreview?.ToLower().Contains(globalSearch) ?? false) || p.SrcPort.ToString().Contains(globalSearch) || p.DstPort.ToString().Contains(globalSearch) || (p.RawData != null && SearchInRawData(p.RawData, globalSearch)));
            if (!string.IsNullOrEmpty(srcIp)) query = query.Where(p => p.SrcIP.ToLower().Contains(srcIp));
            if (!string.IsNullOrEmpty(dstIp)) query = query.Where(p => p.DstIP.ToLower().Contains(dstIp));
            if (!string.IsNullOrEmpty(srcPortStr) && ushort.TryParse(srcPortStr, out ushort sp)) query = query.Where(p => p.SrcPort == sp);
            if (!string.IsNullOrEmpty(dstPortStr) && ushort.TryParse(dstPortStr, out ushort dp)) query = query.Where(p => p.DstPort == dp);
            if (proto != null && proto != "All") query = query.Where(p => p.Protocol == proto);
            if (!string.IsNullOrEmpty(lengthStr) && ushort.TryParse(lengthStr, out ushort ln)) query = query.Where(p => p.Length == ln);

            var result = query.ToList();
            PacketDataGrid.ItemsSource = result;
            FilterResultText.Text = $"Showing {result.Count} of {packetHistory.Count}";
            FilterResultText.Foreground = result.Count > 0 ? new SolidColorBrush(Color.FromRgb(0, 255, 136)) : Brushes.Red;
        }

        private void ClearFilter_Click(object sender, RoutedEventArgs e)
        {
            FilterGlobal.Clear(); FilterSrcIp.Clear(); FilterDstIp.Clear(); FilterSrcPort.Clear(); FilterDstPort.Clear(); FilterProto.SelectedIndex = 0; FilterLength.Clear();
            PacketDataGrid.ItemsSource = packetHistory.GetLastN(1000);
            FilterResultText.Text = $"Buffer: {packetHistory.Count:N0} / {packetHistory.Capacity:N0}";
            FilterResultText.Foreground = new SolidColorBrush(Color.FromRgb(0, 255, 136));
        }

        private void ApplyCapacity_Click(object sender, RoutedEventArgs e)
        {
            if (int.TryParse(CapacityTextBox.Text, out int newCapacity))
            {
                newCapacity = Math.Max(1000, Math.Min(newCapacity, 10000000));
                if (newCapacity > 1000000)
                {
                    if (MessageBox.Show($"Setting capacity to {newCapacity:N0} packets will use approx {(newCapacity * 500L) / 1024 / 1024} MB of RAM.\nContinue?", "Warning", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
                }
                packetHistory.Resize(newCapacity);
                userDesiredCapacity = newCapacity;
                CapacityTextBox.Text = newCapacity.ToString();
            }
        }

        private void ResetAllData()
        {
            lock (protocolCounts) protocolCounts.Clear();
            lock (packetHistory) packetHistory.Clear();
            protocolSeriesMap.Clear(); protocolValuesMap.Clear(); protocolStatsMap.Clear(); protocolStatsList.Clear(); seriesCollection.Clear();
            totalPackets = 0;
            ProtocolPieChart.Series = seriesCollection;
            PacketDataGrid.ItemsSource = null;
            TotalPacketsText.Text = "Total Packets: 0";
            PacketsPerSecondText.Text = "Packets/sec: 0";
            ppsValues.Clear(); ppsHistory.Clear(); packetsInCurrentSecond = 0; peakPps = 0;
            CurrentPpsText.Text = "0"; PeakPpsText.Text = "0"; AvgPpsText.Text = "0";
            bpsValues.Clear(); bpsHistory.Clear(); bpsValuesList.Clear(); bytesInCurrentSecond = 0; totalBytes = 0; peakBps = 0;
            CurrentBpsText.Text = "0 B/s"; PeakBpsText.Text = "0 B/s"; AvgBpsText.Text = "0 B/s"; TotalBytesText.Text = "Total: 0 B";
            backgroundAnalyzer?.Clear();
            srcIpCounts.Clear(); dstIpCounts.Clear(); srcIpStatsMap.Clear(); dstIpStatsMap.Clear(); topSourceList.Clear(); topDestList.Clear();
            lock (detectedFilesMap) { detectedFilesMap.Clear(); detectedFilesList.Clear(); }
            HttpCountText.Text = "0"; DnsCountText.Text = "0"; TlsCountText.Text = "0";
        }

        private void PacketDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (PacketDataGrid.SelectedItem is PacketRecord packet) DisplayPacketDetails(packet);
        }

        private void DisplayPacketDetails(PacketRecord packet)
        {
            PacketDetailsTree.Items.Clear();
            HexDumpText.Clear();
            if (packet.RawData == null || packet.RawData.Length == 0) { PacketDetailsTree.Items.Add(new TreeViewItem { Header = "No data available" }); return; }

            byte[] data = packet.RawData;
            var root = new TreeViewItem { Header = $"Frame: {packet.Length} bytes on wire" };

            if (data.Length >= 14)
            {
                var eth = new TreeViewItem { Header = "Ethernet II" };
                eth.Items.Add(new TreeViewItem { Header = $"Destination: {BitConverter.ToString(data, 0, 6).Replace("-", ":")}" });
                eth.Items.Add(new TreeViewItem { Header = $"Source: {BitConverter.ToString(data, 6, 6).Replace("-", ":")}" });
                ushort ethType = (ushort)(data[12] << 8 | data[13]);
                eth.Items.Add(new TreeViewItem { Header = $"Type: {(ethType == 0x0800 ? "IPv4" : ethType == 0x0806 ? "ARP" : ethType == 0x86DD ? "IPv6" : $"0x{ethType:X4}")} (0x{ethType:X4})" });
                root.Items.Add(eth);
            }

            if (data.Length >= 34 && (data[12] << 8 | data[13]) == 0x0800)
            {
                byte ver_ihl = data[14];
                byte ihl = (byte)((ver_ihl & 0x0F) * 4);
                var ip = new TreeViewItem { Header = "Internet Protocol Version 4" };
                ip.Items.Add(new TreeViewItem { Header = $"Version: {ver_ihl >> 4}" });
                ip.Items.Add(new TreeViewItem { Header = $"Header Length: {ihl} bytes" });
                ip.Items.Add(new TreeViewItem { Header = $"Total Length: {(data[16] << 8 | data[17])}" });
                ip.Items.Add(new TreeViewItem { Header = $"TTL: {data[22]}" });
                ip.Items.Add(new TreeViewItem { Header = $"Protocol: {packet.Protocol} ({data[23]})" });
                ip.Items.Add(new TreeViewItem { Header = $"Source: {packet.SrcIP}" });
                ip.Items.Add(new TreeViewItem { Header = $"Destination: {packet.DstIP}" });
                root.Items.Add(ip);

                int transportStart = 14 + ihl;
                if (data[23] == 6 && data.Length >= transportStart + 20)
                {
                    var tcp = new TreeViewItem { Header = "Transmission Control Protocol" };
                    tcp.Items.Add(new TreeViewItem { Header = $"Source Port: {packet.SrcPort}" });
                    tcp.Items.Add(new TreeViewItem { Header = $"Destination Port: {packet.DstPort}" });
                    root.Items.Add(tcp);
                }
                else if (data[23] == 17 && data.Length >= transportStart + 8)
                {
                    var udp = new TreeViewItem { Header = "User Datagram Protocol" };
                    udp.Items.Add(new TreeViewItem { Header = $"Source Port: {packet.SrcPort}" });
                    udp.Items.Add(new TreeViewItem { Header = $"Destination Port: {packet.DstPort}" });
                    root.Items.Add(udp);
                }
            }
            PacketDetailsTree.Items.Add(root);
            HexDumpText.Text = FormatHexDump(data);
        }

        private string FormatHexDump(byte[] data)
        {
            var sb = new System.Text.StringBuilder();
            for (int i = 0; i < data.Length; i += 16)
            {
                sb.AppendFormat("{0:X8}  ", i);
                for (int j = 0; j < 16; j++) { if (i + j < data.Length) sb.AppendFormat("{0:X2} ", data[i + j]); else sb.Append("   "); if (j == 7) sb.Append(" "); }
                sb.Append(" |");
                for (int j = 0; j < 16 && i + j < data.Length; j++) { byte b = data[i + j]; sb.Append(b >= 32 && b <= 126 ? (char)b : '.'); }
                sb.AppendLine("|");
            }
            return sb.ToString();
        }

        private bool SearchInRawData(byte[] rawData, string searchTerm)
        {
            if (rawData == null || rawData.Length == 0) return false;
            if (BitConverter.ToString(rawData).Replace("-", "").ToLower().Contains(searchTerm.ToLower())) return true;
            if (System.Text.Encoding.ASCII.GetString(rawData).ToLower().Contains(searchTerm.ToLower())) return true;
            try { if (System.Text.Encoding.UTF8.GetString(rawData).ToLower().Contains(searchTerm.ToLower())) return true; } catch { }
            return false;
        }

        private void TopIpList_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (sender is ListBox listBox && listBox.SelectedItem is IpStats selectedIp) { FilterGlobal.Text = selectedIp.IP; ApplyFilter_Click(null, null); }
        }

        private void DetectedFilesList_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (DetectedFilesList.SelectedItem is DetectedFile file) { FilterGlobal.Text = file.Name; ApplyFilter_Click(null, null); }
        }

        private void CapturedFilesGrid_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (CapturedFilesGrid.SelectedItem is CapturedFileRecord file && File.Exists(file.FilePath))
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo { FileName = file.FilePath, UseShellExecute = true });
        }

        private void TalkerModeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e) { }

        private void ExportCsv_Click(object sender, RoutedEventArgs e)
        {
            var sfd = new Microsoft.Win32.SaveFileDialog { Filter = "CSV Files (*.csv)|*.csv", FileName = $"PacketStreamer_{DateTime.Now:yyyyMMdd_HHmmss}.csv" };
            if (sfd.ShowDialog() != true) return;
            try
            {
                var packets = PacketDataGrid.ItemsSource as List<PacketRecord> ?? packetHistory.ToList();
                using var w = new StreamWriter(sfd.FileName, false, System.Text.Encoding.UTF8);
                w.WriteLine("Timestamp,Source IP,Dest IP,Protocol,Src Port,Dst Port,Length");
                foreach (var p in packets) w.WriteLine($"\"{p.Timestamp}\",\"{p.SrcIP}\",\"{p.DstIP}\",\"{p.Protocol}\",{p.SrcPort},{p.DstPort},{p.Length}");
                MessageBox.Show($"Exported {packets.Count} packets.", "Done");
            }
            catch (Exception ex) { MessageBox.Show($"Error: {ex.Message}"); }
        }

        private void ExportPcap_Click(object sender, RoutedEventArgs e)
        {
            var sfd = new Microsoft.Win32.SaveFileDialog { Filter = "PCAP Files (*.pcap)|*.pcap", FileName = $"PacketStreamer_{DateTime.Now:yyyyMMdd_HHmmss}.pcap" };
            if (sfd.ShowDialog() != true) return;
            try
            {
                var packets = PacketDataGrid.ItemsSource as List<PacketRecord> ?? packetHistory.ToList();
                using var fs = new FileStream(sfd.FileName, FileMode.Create);
                using var w = new BinaryWriter(fs);
                w.Write((uint)0xA1B2C3D4); w.Write((ushort)2); w.Write((ushort)4); w.Write(0); w.Write((uint)0); w.Write((uint)65535); w.Write((uint)1);
                foreach (var p in packets)
                {
                    if (p.RawData == null || p.RawData.Length == 0) continue;
                    w.Write(p.TimestampSec); w.Write(p.TimestampUsec); w.Write((uint)p.RawData.Length); w.Write((uint)p.RawData.Length); w.Write(p.RawData);
                }
                MessageBox.Show($"Exported {packets.Count} packets to PCAP.", "Done");
            }
            catch (Exception ex) { MessageBox.Show($"Error: {ex.Message}"); }
        }

        private List<PacketRecord> GetCurrentDisplayedPackets()
        {
            if (PacketDataGrid.ItemsSource is List<PacketRecord> list) return list;
            return packetHistory.ToList();
        }

        private void AnalyzePacketForFiles(PacketRecord packet)
        {
            if (packet.RawData == null || packet.RawData.Length < 34) return;
            try
            {
                byte[] data = packet.RawData;
                if ((data[12] << 8 | data[13]) != 0x0800) return;
                byte ihl = (byte)((data[14] & 0x0F) * 4);
                byte protocol = data[23];
                int transportStart = 14 + ihl;
                int appPayloadStart = -1, appPayloadLen = 0;
                if (protocol == 6 && data.Length >= transportStart + 20) { appPayloadStart = transportStart + ((data[transportStart + 12] >> 4) * 4); appPayloadLen = data.Length - appPayloadStart; }
                else if (protocol == 17 && data.Length >= transportStart + 8) { appPayloadStart = transportStart + 8; appPayloadLen = data.Length - appPayloadStart; }
                if (appPayloadStart < 0 || appPayloadLen <= 0) return;

                string type = null, name = null;
                if (packet.SrcPort == 80 || packet.DstPort == 80) { name = ParseHttp(data, appPayloadStart, appPayloadLen); if (name != null) type = "HTTP"; }
                else if (packet.SrcPort == 53 || packet.DstPort == 53) { name = ParseDns(data, appPayloadStart, appPayloadLen); if (name != null) type = "DNS"; }
                else if (packet.SrcPort == 443 || packet.DstPort == 443) { name = ParseTlsSni(data, appPayloadStart, appPayloadLen); if (name != null) type = "TLS"; }

                if (type != null && name != null) RegisterDetectedFile(type, name, packet);
            }
            catch { }
        }

        private string ParseHttp(byte[] data, int start, int len)
        {
            if (len < 10) return null;
            try
            {
                string payload = System.Text.Encoding.ASCII.GetString(data, start, Math.Min(len, 2000));
                if (!payload.StartsWith("GET ") && !payload.StartsWith("POST ") && !payload.StartsWith("HEAD ")) return null;
                int urlStart = payload.IndexOf(' ') + 1;
                int urlEnd = payload.IndexOf(" HTTP/");
                if (urlEnd < 0) return null;
                string url = payload.Substring(urlStart, urlEnd - urlStart);
                int hostIdx = payload.IndexOf("Host: ", StringComparison.OrdinalIgnoreCase);
                string host = "";
                if (hostIdx >= 0) { int hEnd = payload.IndexOf("\r\n", hostIdx + 6); if (hEnd > hostIdx + 6) host = payload.Substring(hostIdx + 6, hEnd - hostIdx - 6).Trim(); }
                return string.IsNullOrEmpty(host) ? url : $"{host}{url}";
            }
            catch { return null; }
        }

        private string ParseDns(byte[] data, int start, int len)
        {
            if (len < 12) return null;
            try
            {
                int offset = start + 12;
                var sb = new System.Text.StringBuilder();
                while (offset < data.Length)
                {
                    byte labelLen = data[offset++];
                    if (labelLen == 0) break;
                    if ((labelLen & 0xC0) == 0xC0) { offset++; break; }
                    if (offset + labelLen > data.Length) break;
                    if (sb.Length > 0) sb.Append('.');
                    for (int i = 0; i < labelLen; i++) sb.Append((char)data[offset++]);
                }
                return sb.Length > 0 && sb.Length < 256 ? sb.ToString() : null;
            }
            catch { return null; }
        }

        private string ParseTlsSni(byte[] data, int start, int len)
        {
            if (len < 43 || data[start] != 0x16) return null;
            try
            {
                int offset = start + 5;
                if (data[offset] != 0x01) return null;
                offset += 38;
                if (offset >= data.Length) return null;
                offset += data[offset] + 1;
                if (offset + 2 >= data.Length) return null;
                ushort cipherLen = (ushort)((data[offset] << 8) | data[offset + 1]);
                offset += 2 + cipherLen;
                if (offset >= data.Length) return null;
                offset += data[offset] + 1;
                if (offset + 2 >= data.Length) return null;
                ushort extLen = (ushort)((data[offset] << 8) | data[offset + 1]);
                offset += 2;
                int extEnd = offset + extLen;
                while (offset + 4 < extEnd && offset + 4 < data.Length)
                {
                    ushort extType = (ushort)((data[offset] << 8) | data[offset + 1]);
                    ushort extDataLen = (ushort)((data[offset + 2] << 8) | data[offset + 3]);
                    offset += 4;
                    if (extType == 0x0000 && offset + 5 < data.Length)
                    {
                        ushort nameLen = (ushort)((data[offset + 3] << 8) | data[offset + 4]);
                        offset += 5;
                        if (offset + nameLen <= data.Length && nameLen < 256) return System.Text.Encoding.ASCII.GetString(data, offset, nameLen);
                    }
                    offset += extDataLen;
                }
            }
            catch { }
            return null;
        }

        private void RegisterDetectedFile(string type, string name, PacketRecord packet)
        {
            string key = $"{type}|{name}";
            lock (detectedFilesMap)
            {
                if (!detectedFilesMap.ContainsKey(key))
                    detectedFilesMap[key] = new DetectedFile { Type = type, Name = name, SrcIP = packet.SrcIP, DstIP = packet.DstIP, SrcPort = packet.SrcPort, DstPort = packet.DstPort, HitCount = 1 };
                else
                    detectedFilesMap[key].HitCount++;
            }
        }

        private void ExtractAndSaveHttpFile(PacketRecord packet)
        {
            if (packet.SrcPort != 80 && packet.DstPort != 80) return;
            if (packet.RawData == null || packet.RawData.Length < 50) return;
            try
            {
                string payload = System.Text.Encoding.ASCII.GetString(packet.RawData);
                if (!payload.Contains("HTTP/1.1 200") && !payload.Contains("HTTP/1.0 200")) return;
                int headerEnd = payload.IndexOf("\r\n\r\n");
                if (headerEnd < 0) return;
                string ct = "application/octet-stream";
                int ctIdx = payload.IndexOf("Content-Type:", StringComparison.OrdinalIgnoreCase);
                if (ctIdx > 0 && ctIdx < headerEnd) { int ctEnd = payload.IndexOf("\r\n", ctIdx); ct = payload.Substring(ctIdx + 13, ctEnd - ctIdx - 13).Trim(); }
                string ext = ".bin";
                if (ct.Contains("html")) ext = ".html"; else if (ct.Contains("css")) ext = ".css"; else if (ct.Contains("javascript")) ext = ".js"; else if (ct.Contains("png")) ext = ".png"; else if (ct.Contains("jpeg") || ct.Contains("jpg")) ext = ".jpg"; else if (ct.Contains("gif")) ext = ".gif"; else if (ct.Contains("json")) ext = ".json";

                string fileName = $"capture_{DateTime.Now:yyyyMMdd_HHmmss_fff}{ext}";
                string fullPath = Path.Combine(captureFolder, fileName);
                int bodyStart = headerEnd + 4;
                int bodyLen = packet.RawData.Length - bodyStart;
                if (bodyLen > 0)
                {
                    byte[] fileData = new byte[bodyLen];
                    Array.Copy(packet.RawData, bodyStart, fileData, 0, bodyLen);
                    File.WriteAllBytes(fullPath, fileData);
                    Application.Current.Dispatcher.Invoke(() => capturedFilesList.Insert(0, new CapturedFileRecord { Timestamp = packet.Timestamp, SourceIP = packet.SrcIP, DestIP = packet.DstIP, ContentType = ct, FileName = fileName, FilePath = fullPath, FileSize = bodyLen }));
                }
            }
            catch { }
        }

        protected override void OnClosed(EventArgs e)
        {
            backgroundAnalyzer?.Stop();
            CleanupWinsock();
            base.OnClosed(e);
        }
    }

    public class ProtocolToColorConverter : System.Windows.Data.IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value is string p) return p switch { "TCP" => new SolidColorBrush(Color.FromRgb(0, 212, 255)), "UDP" => new SolidColorBrush(Color.FromRgb(0, 255, 136)), "ICMP" => new SolidColorBrush(Color.FromRgb(255, 68, 68)), _ => Brushes.Gray };
            return Brushes.Gray;
        }
        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture) => throw new NotImplementedException();
    }

    public class ProtocolToBackgroundConverter : System.Windows.Data.IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value is string p)
            {
                Color c = p switch { "TCP" => Color.FromRgb(0, 212, 255), "UDP" => Color.FromRgb(0, 255, 136), "ICMP" => Color.FromRgb(255, 68, 68), _ => Color.FromRgb(150, 150, 150) };
                var b = new SolidColorBrush(c) { Opacity = 0.10 };
                b.Freeze();
                return b;
            }
            return Brushes.Transparent;
        }
        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture) => throw new NotImplementedException();
    }
}