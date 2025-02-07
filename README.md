# Md5Finder
第一版
```
public class Md5Finder
{
    // 预定义字符集，按照英文字母出现频率排序
    private static ReadOnlyMemory<char> DefaultCharset = "etaoinshrdlcumwfgypbvkjxqzETAOINSHRDLCUMWFGYPBVKJXQZ0123456789".AsMemory();

    /// <summary>
    /// 查找一个字符串，使其MD5值的前缀与目标前缀匹配
    /// </summary>
    /// <param name="targetPrefix">目标MD5值的前缀</param>
    /// <returns>找到的匹配字符串，如果未找到则返回null</returns>
    public static async Task<string> FindStringByMd5PrefixAsync(string targetPrefix)
    {
        // 验证输入
        if (string.IsNullOrEmpty(targetPrefix) || !targetPrefix.All(c => char.IsLetterOrDigit(c)))
        {
            throw new ArgumentException("目标前缀必须是有效的十六进制字符串");
        }

        // 从长度1开始逐步增加字符串长度，最多尝试到长度10
        for (int length = 1; length <= 10; length++)
        {
            var result = await TryFindMatchParallelAsync(DefaultCharset, length, targetPrefix);
            if (result != null)
            {
                return result;
            }
        }

        return null;
    }

    private static async Task<string> TryFindMatchParallelAsync(ReadOnlyMemory<char> charset, int length, string targetPrefix)
    {
        var result = new ConcurrentBag<string>();
        using var cts = new CancellationTokenSource();

        // 计算总的组合数
        long totalCombinations = (long)Math.Pow(charset.Length, length);

        // 优化：使用处理器核心数的2倍作为并行度
        int processorCount = Environment.ProcessorCount;
        long batchSize = Math.Max(100_000, totalCombinations / (processorCount * 2));

        // 预处理目标前缀
        (byte[] targetPrefixBytes, int prefixNibbles) = PreprocessTargetPrefix(targetPrefix);

        // 创建任务数组
        var tasks = new List<Task>();

        // 创建共享的对象池来重用MD5实例
        using var md5Pool = new ObjectPool<MD5>(
            () => MD5.Create(),
            maxSize: processorCount * 2);

        // 将字符集转换为数组，以便在任务中安全使用
        char[] charsetArray = charset.ToArray();

        for (long start = 0; start < totalCombinations; start += batchSize)
        {
            long end = Math.Min(start + batchSize, totalCombinations);
            long capturedStart = start;
            long capturedEnd = end;

            var task = Task.Run(() =>
            {
                // 从对象池获取MD5实例
                using var md5Lease = md5Pool.Rent();
                var md5 = md5Lease.Instance;

                // 使用可重用的缓冲区
                using var inputBufferLease = MemoryPool<byte>.Shared.Rent(length * 4);
                using var hashBufferLease = MemoryPool<byte>.Shared.Rent(16);
                var inputBuffer = inputBufferLease.Memory;
                var hashBuffer = hashBufferLease.Memory;
                var current = new char[length];

                for (long i = capturedStart; i < capturedEnd && !cts.Token.IsCancellationRequested; i++)
                {
                    // 生成字符串
                    GenerateString(i, charsetArray, current);

                    // 计算UTF8字节
                    int bytesWritten = Encoding.UTF8.GetBytes(current, inputBuffer.Span);

                    // 计算MD5
                    md5.TryComputeHash(inputBuffer.Span[..bytesWritten], hashBuffer.Span, out _);

                    // 检查前缀匹配
                    if (IsMatch(hashBuffer.Span, targetPrefixBytes, prefixNibbles))
                    {
                        result.Add(new string(current));
                        cts.Cancel();
                        break;
                    }
                }
            }, cts.Token);

            tasks.Add(task);
        }

        try
        {
            await Task.WhenAll(tasks);
        }
        catch (OperationCanceledException)
        {
            // 忽略取消异常
        }

        return result.FirstOrDefault();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void GenerateString(long index, char[] charset, Span<char> result)
    {
        int charsetLength = charset.Length;
        for (int pos = result.Length - 1; pos >= 0; pos--)
        {
            result[pos] = charset[(int)(index % charsetLength)];
            index /= charsetLength;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsMatch(ReadOnlySpan<byte> hash, byte[] targetPrefix, int prefixNibbles)
    {
        int fullBytes = prefixNibbles / 2;
        for (int i = 0; i < fullBytes; i++)
        {
            if ((byte)((hash[i] >> 4) | (hash[i] << 4)) != targetPrefix[i])
                return false;
        }

        if (prefixNibbles % 2 == 1)
        {
            byte lastNibble = (byte)(hash[fullBytes] >> 4);
            if (lastNibble != (targetPrefix[fullBytes] >> 4))
                return false;
        }

        return true;
    }

    private static (byte[] bytes, int nibbles) PreprocessTargetPrefix(string targetPrefix)
    {
        int prefixNibbles = targetPrefix.Length;
        byte[] targetPrefixBytes = new byte[prefixNibbles / 2 + (prefixNibbles % 2 == 1 ? 1 : 0)];

        for (int i = 0; i < prefixNibbles; i += 2)
        {
            targetPrefixBytes[i / 2] = (byte)(
                (HexToByte(targetPrefix[i]) << 4) |
                (i + 1 < prefixNibbles ? HexToByte(targetPrefix[i + 1]) : 0)
            );
        }

        return (targetPrefixBytes, prefixNibbles);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte HexToByte(char hex) => (byte)(
        hex >= '0' && hex <= '9' ? hex - '0' :
        hex >= 'a' && hex <= 'f' ? hex - 'a' + 10 :
        hex >= 'A' && hex <= 'F' ? hex - 'A' + 10 : 0
    );
}

// 用于管理对象池的辅助类
internal sealed class ObjectPool<T> : IDisposable where T : class
{
    private readonly ConcurrentBag<T> _pool;
    private readonly Func<T> _factory;
    private readonly int _maxSize;
    private int _count;

    public ObjectPool(Func<T> factory, int maxSize)
    {
        _factory = factory;
        _maxSize = maxSize;
        _pool = new ConcurrentBag<T>();
    }

    public PooledObject Rent()
    {
        if (!_pool.TryTake(out var item))
        {
            item = _factory();
            Interlocked.Increment(ref _count);
        }
        return new PooledObject(this, item);
    }

    private void Return(T item)
    {
        if (_count <= _maxSize)
        {
            _pool.Add(item);
        }
        else
        {
            if (item is IDisposable disposable)
            {
                disposable.Dispose();
            }
            Interlocked.Decrement(ref _count);
        }
    }

    public void Dispose()
    {
        foreach (var item in _pool)
        {
            if (item is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
        _pool.Clear();
    }

    public readonly struct PooledObject : IDisposable
    {
        private readonly ObjectPool<T> _pool;
        public readonly T Instance;

        public PooledObject(ObjectPool<T> pool, T instance)
        {
            _pool = pool;
            Instance = instance;
        }

        public void Dispose() => _pool.Return(Instance);
    }
}
```
第二版
```
public class Md5Finder
{
    // 预定义字符集，按照英文字母出现频率排序
    private static ReadOnlyMemory<char> DefaultCharset = "etaoinshrdlcumwfgypbvkjxqzETAOINSHRDLCUMWFGYPBVKJXQZ0123456789".AsMemory();

    /// <summary>
    /// 查找一个字符串，使其MD5值的前缀与目标前缀匹配
    /// </summary>
    /// <param name="targetPrefix">目标MD5值的前缀</param>
    /// <returns>找到的匹配字符串，如果未找到则返回null</returns>
    public static async Task<string> FindStringByMd5PrefixAsync(string targetPrefix)
    {
        // 验证输入
        if (string.IsNullOrEmpty(targetPrefix) || !targetPrefix.All(c => char.IsLetterOrDigit(c)))
        {
            throw new ArgumentException("目标前缀必须是有效的十六进制字符串");
        }

        // 从长度1开始逐步增加字符串长度，最多尝试到长度10
        for (int length = 1; length <= 10; length++)
        {
            var result = await TryFindMatchParallelAsync(DefaultCharset, length, targetPrefix);
            if (result != null)
            {
                return result;
            }
        }

        return null;
    }

    private static async Task<string> TryFindMatchParallelAsync(ReadOnlyMemory<char> charset, int length, string targetPrefix)
    {
        var result = new ConcurrentBag<string>();
        using var cts = new CancellationTokenSource();

        // 计算总的组合数
        long totalCombinations = (long)Math.Pow(charset.Length, length);

        // 优化：使用处理器核心数的2倍作为并行度
        int processorCount = Environment.ProcessorCount;
        long batchSize = Math.Max(100_000, totalCombinations / (processorCount * 2));

        // 预处理目标前缀
        (byte[] targetPrefixBytes, int prefixNibbles) = PreprocessTargetPrefix(targetPrefix);

        // 创建任务数组
        var tasks = new List<Task>();

        // 创建共享的对象池来重用MD5实例
        using var md5Pool = new ObjectPool<MD5>(
            () => MD5.Create(),
            maxSize: processorCount * 2);

        // 将字符集转换为数组，以便在任务中安全使用
        char[] charsetArray = charset.ToArray();

        for (long start = 0; start < totalCombinations; start += batchSize)
        {
            long end = Math.Min(start + batchSize, totalCombinations);
            long capturedStart = start;
            long capturedEnd = end;

            var task = Task.Run(() =>
            {
                // 从对象池获取MD5实例
                using var md5Lease = md5Pool.Rent();
                var md5 = md5Lease.Instance;

                // 使用可重用的缓冲区
                using var inputBufferLease = MemoryPool<byte>.Shared.Rent(length * 4);
                using var hashBufferLease = MemoryPool<byte>.Shared.Rent(16);
                var inputBuffer = inputBufferLease.Memory;
                var hashBuffer = hashBufferLease.Memory;
                var current = new char[length];

                for (long i = capturedStart; i < capturedEnd && !cts.Token.IsCancellationRequested; i++)
                {
                    // 生成字符串
                    GenerateString(i, charsetArray, current);

                    // 计算UTF8字节
                    int bytesWritten = Encoding.UTF8.GetBytes(current, inputBuffer.Span);

                    // 计算MD5
                    md5.TryComputeHash(inputBuffer.Span[..bytesWritten], hashBuffer.Span, out _);

                    // 检查前缀匹配
                    if (IsMatch(hashBuffer.Span, targetPrefixBytes, prefixNibbles))
                    {
                        result.Add(new string(current));
                        cts.Cancel();
                        break;
                    }
                }
            }, cts.Token);

            tasks.Add(task);
        }

        try
        {
            await Task.WhenAll(tasks);
        }
        catch (OperationCanceledException)
        {
            // 忽略取消异常
        }

        return result.FirstOrDefault();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void GenerateString(long index, char[] charset, Span<char> result)
    {
        int charsetLength = charset.Length;
        for (int pos = result.Length - 1; pos >= 0; pos--)
        {
            result[pos] = charset[(int)(index % charsetLength)];
            index /= charsetLength;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsMatch(ReadOnlySpan<byte> hash, byte[] targetPrefix, int prefixNibbles)
    {
        int fullBytes = prefixNibbles / 2;
        for (int i = 0; i < fullBytes; i++)
        {
            if ((byte)((hash[i] >> 4) | (hash[i] << 4)) != targetPrefix[i])
                return false;
        }

        if (prefixNibbles % 2 == 1)
        {
            byte lastNibble = (byte)(hash[fullBytes] >> 4);
            if (lastNibble != (targetPrefix[fullBytes] >> 4))
                return false;
        }

        return true;
    }

    private static (byte[] bytes, int nibbles) PreprocessTargetPrefix(string targetPrefix)
    {
        int prefixNibbles = targetPrefix.Length;
        byte[] targetPrefixBytes = new byte[prefixNibbles / 2 + (prefixNibbles % 2 == 1 ? 1 : 0)];

        for (int i = 0; i < prefixNibbles; i += 2)
        {
            targetPrefixBytes[i / 2] = (byte)(
                (HexToByte(targetPrefix[i]) << 4) |
                (i + 1 < prefixNibbles ? HexToByte(targetPrefix[i + 1]) : 0)
            );
        }

        return (targetPrefixBytes, prefixNibbles);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte HexToByte(char hex) => (byte)(
        hex >= '0' && hex <= '9' ? hex - '0' :
        hex >= 'a' && hex <= 'f' ? hex - 'a' + 10 :
        hex >= 'A' && hex <= 'F' ? hex - 'A' + 10 : 0
    );
}

// 用于管理对象池的辅助类
internal sealed class ObjectPool<T> : IDisposable where T : class
{
    private readonly ConcurrentBag<T> _pool;
    private readonly Func<T> _factory;
    private readonly int _maxSize;
    private int _count;

    public ObjectPool(Func<T> factory, int maxSize)
    {
        _factory = factory;
        _maxSize = maxSize;
        _pool = new ConcurrentBag<T>();
    }

    public PooledObject Rent()
    {
        if (!_pool.TryTake(out var item))
        {
            item = _factory();
            Interlocked.Increment(ref _count);
        }
        return new PooledObject(this, item);
    }

    private void Return(T item)
    {
        if (_count <= _maxSize)
        {
            _pool.Add(item);
        }
        else
        {
            if (item is IDisposable disposable)
            {
                disposable.Dispose();
            }
            Interlocked.Decrement(ref _count);
        }
    }

    public void Dispose()
    {
        foreach (var item in _pool)
        {
            if (item is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
        _pool.Clear();
    }

    public readonly struct PooledObject : IDisposable
    {
        private readonly ObjectPool<T> _pool;
        public readonly T Instance;

        public PooledObject(ObjectPool<T> pool, T instance)
        {
            _pool = pool;
            Instance = instance;
        }

        public void Dispose() => _pool.Return(Instance);
    }
}
```
