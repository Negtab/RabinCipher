using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using RabinCipher.Models;

namespace RabinCipher.ViewModels;

public class MainWindowViewModel : INotifyPropertyChanged
{
    private readonly Crypto _crypto = new();

    private string _pText = "";
    private string _qText = "";
    private string _bText = "";
    private string _nText = "";
    private string _statusText = "";
    private string _sourcePreview = "";
    private string _resultPreview = "";
    private double _progress;
    private bool _isBusy;
    private string _openedFilePath = "";
    private bool _isEncryptMode = true;

    public string PText { get => _pText; set { _pText = value; OnPropertyChanged(); TryUpdateN(); } }
    public string QText { get => _qText; set { _qText = value; OnPropertyChanged(); TryUpdateN(); } }
    public string BText { get => _bText; set { _bText = value; OnPropertyChanged(); } }
    public string NText { get => _nText; set { _nText = value; OnPropertyChanged(); } }
    public string StatusText { get => _statusText; set { _statusText = value; OnPropertyChanged(); } }
    public string SourcePreview { get => _sourcePreview; set { _sourcePreview = value; OnPropertyChanged(); } }
    public string ResultPreview { get => _resultPreview; set { _resultPreview = value; OnPropertyChanged(); } }
    public double Progress { get => _progress; set { _progress = value; OnPropertyChanged(); } }
    public bool IsBusy { get => _isBusy; set { _isBusy = value; OnPropertyChanged(); OnPropertyChanged(nameof(IsNotBusy)); } }
    public bool IsNotBusy => !_isBusy;
    public bool IsEncryptMode { get => _isEncryptMode; set { _isEncryptMode = value; OnPropertyChanged(); OnPropertyChanged(nameof(IsDecryptMode)); } }
    public bool IsDecryptMode => !_isEncryptMode;
    public string OpenedFilePath { get => _openedFilePath; set { _openedFilePath = value; OnPropertyChanged(); OnPropertyChanged(nameof(HasFile)); } }
    public bool HasFile => !string.IsNullOrEmpty(_openedFilePath);

    // Последний обработанный результат (байты для сохранения)
    public byte[]? LastResult { get;  set; }

    private void TryUpdateN()
    {
        if (BigInteger.TryParse(_pText, out var p) && BigInteger.TryParse(_qText, out var q) && p > 0 && q > 0)
            NText = (p * q).ToString();
        else
            NText = "";
    }

    public void SetFile(string path, byte[] bytes)
    {
        OpenedFilePath = path;
        SourcePreview = BuildBytePreview(bytes, 128);
        ResultPreview = "";
        StatusText = $"Файл открыт: {Path.GetFileName(path)} ({bytes.Length} байт)";
        LastResult = null;
    }

    public async Task<byte[]?> EncryptAsync(byte[] sourceBytes, IProgress<double> progress, CancellationToken ct)
    {
        if (!TryApplyKeys(out string err)) { StatusText = "Ошибка: " + err; return null; }

        return await Task.Run(() =>
        {
            var result = new List<byte>();
            int total = sourceBytes.Length;
            for (int i = 0; i < total; i++)
            {
                ct.ThrowIfCancellationRequested();
                BigInteger m = sourceBytes[i];
                BigInteger c = _crypto.Cipher(m);
                // Сохраняем шифртекст: 4 байта на каждый байт открытого текста (n < 2^32 в учебном случае)
                byte[] encoded = EncodeNumber(c);
                result.AddRange(encoded);
                progress.Report((i + 1.0) / total * 100);
            }
            return result.ToArray();
        }, ct);
    }

    public async Task<byte[]?> DecryptAsync(byte[] encBytes, IProgress<double> progress, CancellationToken ct)
    {
        if (!TryApplyKeys(out string err)) { StatusText = "Ошибка: " + err; return null; }

        int chunkSize = GetChunkSize();
        if (encBytes.Length % chunkSize != 0)
        {
            StatusText = $"Ошибка: размер файла не кратен {chunkSize} байтам (размер блока для текущего n).";
            return null;
        }

        return await Task.Run(() =>
        {
            var result = new List<byte>();
            int total = encBytes.Length / chunkSize;
            for (int i = 0; i < total; i++)
            {
                ct.ThrowIfCancellationRequested();
                BigInteger c = DecodeNumber(encBytes, i * chunkSize, chunkSize);
                var candidates = _crypto.Decipher(c);
                // Выбираем корректный корень: значение в диапазоне [0, 255]
                BigInteger chosen = -1;
                foreach (var cand in candidates)
                    if (cand >= 0 && cand <= 255) { chosen = cand; break; }
                if (chosen < 0)
                {
                    // Берём первый доступный — пользователь сам разберётся
                    chosen = candidates.Count > 0 ? candidates[0] : 0;
                }
                result.Add((byte)(chosen & 0xFF));
                progress.Report((i + 1.0) / total * 100);
            }
            return result.ToArray();
        }, ct);
    }

    private bool TryApplyKeys(out string error)
    {
        error = "";
        try
        {
            if (!BigInteger.TryParse(_pText, out var p) || p <= 0)
            { error = "Некорректное значение p."; return false; }
            if (!BigInteger.TryParse(_qText, out var q) || q <= 0)
            { error = "Некорректное значение q."; return false; }
            if (p == q)
            { error = "p и q должны быть различными."; return false; }

            _crypto.P = p;
            _crypto.Q = q;

            if (!BigInteger.TryParse(_bText, out var b) || b < 0)
            { error = "Некорректное значение b (должно быть ≥ 0)."; return false; }
            _crypto.B = b;

            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    // Размер блока шифртекста в байтах (минимум, вмещающий N)
    private int GetChunkSize()
    {
        if (!BigInteger.TryParse(_nText, out var n) || n == 0) return 4;
        int bytes = (int)Math.Ceiling(BigInteger.Log(n, 256));
        // Округляем до 1, 2, 4, 8
        if (bytes <= 1) return 1;
        if (bytes <= 2) return 2;
        if (bytes <= 4) return 4;
        return 8;
    }

    private byte[] EncodeNumber(BigInteger c)
    {
        int size = GetChunkSize();
        byte[] buf = new byte[size];
        byte[] raw = c.ToByteArray(); // little-endian
        for (int i = 0; i < Math.Min(raw.Length, size); i++)
            buf[i] = raw[i];
        return buf;
    }

    private BigInteger DecodeNumber(byte[] data, int offset, int size)
    {
        byte[] buf = new byte[size + 1]; // +1 чтобы быть положительным
        Array.Copy(data, offset, buf, 0, size);
        return new BigInteger(buf);
    }

    public static string BuildBytePreview(byte[] bytes, int maxBytes)
    {
        var sb = new StringBuilder();
        int count = Math.Min(bytes.Length, maxBytes);
        for (int i = 0; i < count; i++)
        {
            sb.Append(bytes[i]);
            if (i < count - 1) sb.Append(' ');
        }
        if (bytes.Length > maxBytes) sb.Append(" …");
        return sb.ToString();
    }

    public static string BuildEncryptedPreview(byte[] bytes, int chunkSize, int maxChunks)
    {
        var sb = new StringBuilder();
        int total = bytes.Length / chunkSize;
        int show = Math.Min(total, maxChunks);
        for (int i = 0; i < show; i++)
        {
            byte[] buf = new byte[chunkSize + 1];
            Array.Copy(bytes, i * chunkSize, buf, 0, chunkSize);
            BigInteger val = new BigInteger(buf);
            sb.Append(val);
            if (i < show - 1) sb.Append(' ');
        }
        if (total > maxChunks) sb.Append(" …");
        return sb.ToString();
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}