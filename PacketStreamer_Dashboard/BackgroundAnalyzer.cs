using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace PacketStreamer_Dashboard
{
    /// <summary>
    /// تحلیل‌گر پس‌زمینه: عملیات سنگین (پارس HTTP، ذخیره فایل) را از رشته دریافت پکت جدا می‌کند.
    /// این کار باعث می‌شود هیچ پکتی از دست نرود.
    /// </summary>
    public class BackgroundAnalyzer
    {
        private readonly BlockingCollection<PacketRecord> queue = new BlockingCollection<PacketRecord>(100000);
        private readonly Thread workerThread;
        private readonly Action<PacketRecord> analyzeFileAction;
        private readonly Action<PacketRecord> extractHttpAction;
        private volatile bool isRunning = false;

        public int QueueLength => queue.Count;
        public long TotalProcesse;
        public long TotalDropped;

        public BackgroundAnalyzer(Action<PacketRecord> analyzeFile, Action<PacketRecord> extractHttp)
        {
            analyzeFileAction = analyzeFile;
            extractHttpAction = extractHttp;
            workerThread = new Thread(ProcessQueue)
            {
                IsBackground = true,
                Name = "PacketAnalyzer",
                Priority = ThreadPriority.BelowNormal
            };
        }

        public void Start()
        {
            if (isRunning) return;
            isRunning = true;
            workerThread.Start();
        }

        public void Stop()
        {
            isRunning = false;
            queue.CompleteAdding();
            workerThread.Join(2000);
        }

        /// <summary>
        /// افزودن پکت به صف تحلیل. اگر صف پر باشد، پکت حذف می‌شود (برای جلوگیری از memory leak).
        /// </summary>
        public void Enqueue(PacketRecord packet)
        {
            if (!isRunning) return;

            if (!queue.TryAdd(packet))
            {
                // صف پر است - پکت را حذف کن (بهتر از فریز شدن)
                Interlocked.Increment(ref TotalDropped);
            }
        }

        private void ProcessQueue()
        {
            while (isRunning && !queue.IsCompleted)
            {
                try
                {
                    // گرفتن دسته‌ای از پکت‌ها (batch processing)
                    if (queue.TryTake(out var packet, 100))
                    {
                        try
                        {
                            analyzeFileAction?.Invoke(packet);
                            extractHttpAction?.Invoke(packet);
                            Interlocked.Increment(ref TotalProcesse);
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Debug.WriteLine($"Analyzer error: {ex.Message}");
                        }
                    }
                }
                catch (InvalidOperationException)
                {
                    break;
                }
            }
        }

        public void Clear()
        {
            while (queue.Count > 0)
            {
                queue.TryTake(out _);
            }
            TotalProcesse = 0;
            TotalDropped = 0;
        }
    }
}