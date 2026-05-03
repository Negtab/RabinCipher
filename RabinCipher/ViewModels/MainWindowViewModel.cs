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

    private byte[]? _sourceBytes;

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

    private string _pError = "";
    private string _qError = "";
    private string _bError = "";

    // ── Свойства ошибок ──────────────────────────────────────────────────────
    public string PError { get => _pError; set { _pError = value; OnPropertyChanged(); OnPropertyChanged(nameof(HasPError)); OnPropertyChanged(nameof(CanRun)); } }
    public string QError { get => _qError; set { _qError = value; OnPropertyChanged(); OnPropertyChanged(nameof(HasQError)); OnPropertyChanged(nameof(CanRun)); } }
    public string BError { get => _bError; set { _bError = value; OnPropertyChanged(); OnPropertyChanged(nameof(HasBError)); OnPropertyChanged(nameof(CanRun)); } }
    public bool HasPError => !string.IsNullOrEmpty(_pError);
    public bool HasQError => !string.IsNullOrEmpty(_qError);
    public bool HasBError => !string.IsNullOrEmpty(_bError);

    // ── Основные свойства ────────────────────────────────────────────────────
    public string PText
    {
        get => _pText;
        set { _pText = value; OnPropertyChanged(); ValidateP(); TryUpdateN(); ValidateB(); }
    }
    public string QText
    {
        get => _qText;
        set { _qText = value; OnPropertyChanged(); ValidateQ(); TryUpdateN(); ValidateB(); }
    }
    public string BText
    {
        get => _bText;
        set { _bText = value; OnPropertyChanged(); ValidateB(); }
    }
    public string NText { get => _nText; set { _nText = value; OnPropertyChanged(); } }
    public string StatusText { get => _statusText; set { _statusText = value; OnPropertyChanged(); } }
    public string SourcePreview { get => _sourcePreview; set { _sourcePreview = value; OnPropertyChanged(); } }
    public string ResultPreview { get => _resultPreview; set { _resultPreview = value; OnPropertyChanged(); } }
    public double Progress { get => _progress; set { _progress = value; OnPropertyChanged(); } }
    public bool IsBusy { get => _isBusy; set { _isBusy = value; OnPropertyChanged(); OnPropertyChanged(nameof(IsNotBusy)); OnPropertyChanged(nameof(CanRun)); } }
    public bool IsNotBusy => !_isBusy;
    public bool CanRun => IsNotBusy && HasFile
                          && !HasPError && !string.IsNullOrWhiteSpace(_pText)
                          && !HasQError && !string.IsNullOrWhiteSpace(_qText)
                          && !HasBError && !string.IsNullOrWhiteSpace(_bText);

    public bool IsEncryptMode
    {
        get => _isEncryptMode;
        set { _isEncryptMode = value; OnPropertyChanged(); OnPropertyChanged(nameof(IsDecryptMode)); RefreshSourcePreview(); }
    }
    public bool IsDecryptMode => !_isEncryptMode;
    public string OpenedFilePath { get => _openedFilePath; set { _openedFilePath = value; OnPropertyChanged(); OnPropertyChanged(nameof(HasFile)); OnPropertyChanged(nameof(CanRun)); } }
    public bool HasFile => !string.IsNullOrEmpty(_openedFilePath);
    public byte[]? LastResult { get; set; }

    // ── Валидация ─────────────────────────────────────────────────────────────
    private void ValidateP()
    {
        if (string.IsNullOrWhiteSpace(_pText)) { PError = ""; return; }
        if (!BigInteger.TryParse(_pText, out var p) || p < 2) { PError = "Введите целое число ≥ 2."; return; }
        if (!Crypto.IsPrime(p)) { PError = $"{p} — не простое."; return; }
        if (p % 4 != 3) { PError = $"p ≢ 3 (mod 4). Подходит: {NextValidPrime(p)}."; return; }
        if (BigInteger.TryParse(_qText, out var q) && q == p) { PError = "p и q должны различаться."; return; }
        PError = "";
    }

    private void ValidateQ()
    {
        if (string.IsNullOrWhiteSpace(_qText)) { QError = ""; return; }
        if (!BigInteger.TryParse(_qText, out var q) || q < 2) { QError = "Введите целое число ≥ 2."; return; }
        if (!Crypto.IsPrime(q)) { QError = $"{q} — не простое."; return; }
        if (q % 4 != 3) { QError = $"q ≢ 3 (mod 4). Подходит: {NextValidPrime(q)}."; return; }
        if (BigInteger.TryParse(_pText, out var p) && p == q) { QError = "p и q должны различаться."; return; }
        if (BigInteger.TryParse(_pText, out var p2) && p2 > 1 && p2 * q <= 255)
        { QError = $"n = p·q = {p2 * q} ≤ 255. Нужно n > 255."; return; }
        QError = "";
    }

    private void ValidateB()
    {
        if (string.IsNullOrWhiteSpace(_bText)) { BError = ""; return; }
        if (!BigInteger.TryParse(_bText, out var b)) { BError = "Введите целое число."; return; }
        if (b < 1) { BError = "b должно быть натуральным (b ≥ 1)."; return; }
        if (!string.IsNullOrEmpty(_nText) && BigInteger.TryParse(_nText, out var n) && n > 0 && b >= n)
        { BError = $"b < n = {n}."; return; }
        BError = "";
    }

    private static BigInteger NextValidPrime(BigInteger start)
    {
        BigInteger c = start + 1;
        while (!Crypto.IsPrime(c) || c % 4 != 3) c++;
        return c;
    }

    private void TryUpdateN()
    {
        if (BigInteger.TryParse(_pText, out var p) && BigInteger.TryParse(_qText, out var q) && p > 1 && q > 1)
            NText = (p * q).ToString();
        else
            NText = "";
    }

    // ── Файл ─────────────────────────────────────────────────────────────────
    public void SetFile(string path, byte[] bytes)
    {
        _sourceBytes = bytes;
        OpenedFilePath = path;
        RefreshSourcePreview();
        ResultPreview = "";
        StatusText = $"Файл открыт: {Path.GetFileName(path)} ({bytes.Length} байт)";
        LastResult = null;
    }

    private void RefreshSourcePreview()
    {
        if (_sourceBytes == null) return;

        if (IsDecryptMode)
        {
            // Зашифрованный файл — текстовый, числа через пробел
            // Показываем первые 64 числа как есть
            try
            {
                string text = Encoding.UTF8.GetString(_sourceBytes);
                var parts = text.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                int show = Math.Min(parts.Length, 64);
                SourcePreview = string.Join(" ", parts[..show]) + (parts.Length > 64 ? " …" : "");
            }
            catch
            {
                SourcePreview = "(не удалось прочитать как текст)";
            }
        }
        else
        {
            // Исходный файл — байты в десятичном виде
            SourcePreview = BuildBytePreview(_sourceBytes, 128);
        }
    }

    // ── Шифрование ───────────────────────────────────────────────────────────
    // Формат зашифрованного файла: числа через пробел в текстовом виде
    // Например: "615 23 176 2945 ..."
    public async Task<byte[]?> EncryptAsync(byte[] src, IProgress<double> progress, CancellationToken ct)
    {
        if (!TryApplyKeys(out string err)) { StatusText = "Ошибка: " + err; return null; }

        if (_crypto.N <= 255)
        {
            StatusText = "Ошибка: n = p·q должно быть > 255.";
            return null;
        }

        return await Task.Run(() =>
        {
            var sb = new StringBuilder();
            for (int i = 0; i < src.Length; i++)
            {
                ct.ThrowIfCancellationRequested();

                BigInteger m = src[i];
                BigInteger c = _crypto.Cipher(m);

                if (i > 0) sb.Append(' ');
                sb.Append(c);

                progress.Report((i + 1.0) / src.Length * 100);
            }
            return Encoding.UTF8.GetBytes(sb.ToString());
        }, ct);
    }

    // ── Дешифрование ─────────────────────────────────────────────────────────
    // Читаем числа через пробел, для каждого берём первый корень < 256
    public async Task<byte[]?> DecryptAsync(byte[] enc, IProgress<double> progress, CancellationToken ct)
    {
        if (!TryApplyKeys(out string err)) { StatusText = "Ошибка: " + err; return null; }

        string text;
        try { text = Encoding.UTF8.GetString(enc); }
        catch { StatusText = "Ошибка: файл не является текстовым (зашифрованным)."; return null; }

        var parts = text.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) { StatusText = "Ошибка: файл пуст или имеет неверный формат."; return null; }

        return await Task.Run(() =>
        {
            var result = new List<byte>(parts.Length);
            for (int i = 0; i < parts.Length; i++)
            {
                ct.ThrowIfCancellationRequested();

                if (!BigInteger.TryParse(parts[i], out BigInteger c))
                    throw new InvalidDataException($"Токен {i}: '{parts[i]}' не является числом.");

                var candidates = _crypto.Decipher(c);

                // Берём ПЕРВЫЙ корень < 256 и сразу останавливаемся
                BigInteger chosen = -1;
                foreach (var cand in candidates)
                {
                    if (cand >= 0 && cand < 256)
                    {
                        chosen = cand;
                        break; // первый подходящий — правильный, дальше не смотрим
                    }
                }

                if (chosen < 0)
                    throw new InvalidDataException(
                        $"Токен {i} (c={c}): ни один корень не попал в [0, 255]. " +
                        "Проверьте правильность ключей p, q, b.");

                result.Add((byte)chosen);
                progress.Report((i + 1.0) / parts.Length * 100);
            }
            return result.ToArray();
        }, ct);
    }

    // ── Вспомогательные ──────────────────────────────────────────────────────
    private bool TryApplyKeys(out string error)
    {
        error = "";
        try
        {
            _crypto.P = BigInteger.Parse(_pText);
            _crypto.Q = BigInteger.Parse(_qText);
            _crypto.B = BigInteger.Parse(_bText);
            return true;
        }
        catch (Exception ex) { error = ex.Message; return false; }
    }

    public static string BuildBytePreview(byte[] bytes, int maxBytes)
    {
        var sb = new StringBuilder();
        int count = Math.Min(bytes.Length, maxBytes);
        for (int i = 0; i < count; i++) { sb.Append(bytes[i]); if (i < count - 1) sb.Append(' '); }
        if (bytes.Length > maxBytes) sb.Append(" …");
        return sb.ToString();
    }

    // Для ResultPreview при шифровании — первые maxNums чисел из текстового содержимого
    public static string BuildEncryptedTextPreview(byte[] encBytes, int maxNums)
    {
        try
        {
            string text = Encoding.UTF8.GetString(encBytes);
            var parts = text.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            int show = Math.Min(parts.Length, maxNums);
            return string.Join(" ", parts[..show]) + (parts.Length > maxNums ? " …" : "");
        }
        catch { return "(ошибка чтения)"; }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}