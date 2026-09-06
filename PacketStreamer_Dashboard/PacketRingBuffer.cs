using System;
using System.Collections.Generic;

namespace PacketStreamer_Dashboard
{
    public class PacketRingBuffer
    {
        private PacketRecord[] buffer;
        private int writeIndex = 0;
        private int count = 0;
        private readonly object syncLock = new object();

        public int Capacity { get; private set; }
        public int Count { get { lock (syncLock) return count; } }

        public PacketRingBuffer(int capacity)
        {
            if (capacity < 100) capacity = 100;
            Capacity = capacity;
            buffer = new PacketRecord[capacity];
        }

        public void Add(PacketRecord packet)
        {
            lock (syncLock)
            {
                buffer[writeIndex] = packet;
                writeIndex = (writeIndex + 1) % Capacity;
                if (count < Capacity) count++;
            }
        }

        public List<PacketRecord> ToList()
        {
            lock (syncLock)
            {
                var result = new List<PacketRecord>(count);
                if (count == 0) return result;
                int start = (count < Capacity) ? 0 : writeIndex;
                for (int i = 0; i < count; i++)
                {
                    result.Add(buffer[(start + i) % Capacity]);
                }
                return result;
            }
        }

        public List<PacketRecord> GetLastN(int n)
        {
            lock (syncLock)
            {
                int take = Math.Min(n, count);
                var result = new List<PacketRecord>(take);
                if (take == 0) return result;
                for (int i = 0; i < take; i++)
                {
                    int idx = (writeIndex - 1 - i + Capacity) % Capacity;
                    result.Add(buffer[idx]);
                }
                result.Reverse();
                return result;
            }
        }

        public void Resize(int newCapacity)
        {
            lock (syncLock)
            {
                if (newCapacity < 100) newCapacity = 100;
                var oldList = ToList();
                Capacity = newCapacity;
                buffer = new PacketRecord[newCapacity];
                writeIndex = 0;
                count = 0;
                int startIdx = Math.Max(0, oldList.Count - newCapacity);
                for (int i = startIdx; i < oldList.Count; i++)
                {
                    buffer[writeIndex] = oldList[i];
                    writeIndex = (writeIndex + 1) % newCapacity;
                    count++;
                }
            }
        }

        public void Clear()
        {
            lock (syncLock)
            {
                Array.Clear(buffer, 0, buffer.Length);
                writeIndex = 0;
                count = 0;
            }
        }
    }
}