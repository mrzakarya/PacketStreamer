// ✅ NEW: کلاس برای نمایش فایل/دامنه شناسایی شده
using System.ComponentModel;
using System.Windows.Media;

public class DetectedFile : INotifyPropertyChanged
{
    public string Type { get; set; }      // HTTP, DNS, TLS
    public string Name { get; set; }
    public string SrcIP { get; set; }
    public string DstIP { get; set; }
    public string Ports => $"{SrcPort} → {DstPort}";
    public ushort SrcPort { get; set; }
    public ushort DstPort { get; set; }

    private int hitCount;
    public int HitCount
    {
        get => hitCount;
        set
        {
            hitCount = value;
            OnPropertyChanged(nameof(HitCount));
            OnPropertyChanged(nameof(HitCountText));
        }
    }

    public string HitCountText => $"{HitCount:N0} hits";

    public Brush TypeColor => Type switch
    {
        "HTTP" => new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0, 212, 255)),
        "DNS" => new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 170, 0)),
        "TLS" => new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0, 255, 136)),
        _ => System.Windows.Media.Brushes.Gray
    };

    public string TypeIcon => Type switch
    {
        "HTTP" => "🌐",
        "DNS" => "🔍",
        "TLS" => "🔒",
        _ => "📄"
    };

    public event PropertyChangedEventHandler PropertyChanged;
    protected void OnPropertyChanged(string name) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}