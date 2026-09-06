// ✅ NEW: کلاس برای آمار هر IP
using System.ComponentModel;

public class IpStats : INotifyPropertyChanged
{
    public string Rank { get; set; }
    public string IP { get; set; }

    private int count;
    public int Count
    {
        get => count;
        set
        {
            count = value;
            OnPropertyChanged(nameof(Count));
            OnPropertyChanged(nameof(CountText));
        }
    }

    public string CountText => $"{Count:N0} pkts";

    private double percentage;
    public double Percentage
    {
        get => percentage;
        set
        {
            percentage = value;
            OnPropertyChanged(nameof(Percentage));
            OnPropertyChanged(nameof(PercentageText));
        }
    }

    public string PercentageText => $"{Percentage:F1}%";

    public event PropertyChangedEventHandler PropertyChanged;
    protected void OnPropertyChanged(string name)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}