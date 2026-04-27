using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using RabinCipher.ViewModels;

namespace RabinCipher.Views;

public partial class MainWindow : Window
{
    private MainWindowViewModel Vm => (MainWindowViewModel)DataContext!;

    private byte[]? _sourceBytes;
    private CancellationTokenSource? _cts;

    public MainWindow()
    {
        InitializeComponent();
        DataContext = new MainWindowViewModel();
    }

    // ─── Открыть файл ────────────────────────────────────────────────────────
    private async void OpenFileClick(object? sender, RoutedEventArgs e)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Открыть файл для шифрования / дешифрования",
            AllowMultiple = false
        });

        if (files.Count == 0) return;

        try
        {
            var path = files[0].TryGetLocalPath()!;
            _sourceBytes = await File.ReadAllBytesAsync(path);
            Vm.SetFile(path, _sourceBytes);
        }
        catch (Exception ex)
        {
            Vm.StatusText = "Ошибка открытия файла: " + ex.Message;
        }
    }

    // ─── Выполнить (шифр / дешифр) ───────────────────────────────────────────
    private async void RunClick(object? sender, RoutedEventArgs e)
    {
        if (_sourceBytes == null || _sourceBytes.Length == 0)
        {
            Vm.StatusText = "Сначала откройте файл.";
            return;
        }

        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        Vm.IsBusy = true;
        Vm.Progress = 0;
        Vm.ResultPreview = "";

        var progress = new Progress<double>(v => Dispatcher.UIThread.Post(() => Vm.Progress = v));

        try
        {
            byte[]? result;
            if (Vm.IsEncryptMode)
            {
                Vm.StatusText = "Шифрование…";
                result = await Vm.EncryptAsync(_sourceBytes, progress, _cts.Token);
                if (result != null)
                {
                    Vm.LastResult = result;
                    int chunk = GetChunkSize();
                    Vm.ResultPreview = MainWindowViewModel.BuildEncryptedPreview(result, chunk, 64);
                    Vm.StatusText = $"Шифрование завершено. Размер: {_sourceBytes.Length} → {result.Length} байт.";
                }
            }
            else
            {
                Vm.StatusText = "Дешифрование…";
                result = await Vm.DecryptAsync(_sourceBytes, progress, _cts.Token);
                if (result != null)
                {
                    Vm.LastResult = result;
                    Vm.ResultPreview = MainWindowViewModel.BuildBytePreview(result, 128);
                    Vm.StatusText = $"Дешифрование завершено. Размер: {_sourceBytes.Length} → {result.Length} байт.";
                }
            }
        }
        catch (OperationCanceledException)
        {
            Vm.StatusText = "Операция отменена.";
        }
        catch (Exception ex)
        {
            Vm.StatusText = "Ошибка: " + ex.Message;
        }
        finally
        {
            Vm.IsBusy = false;
            Vm.Progress = 100;
        }
    }

    // ─── Сохранить результат ─────────────────────────────────────────────────
    private async void SaveFileClick(object? sender, RoutedEventArgs e)
    {
        if (Vm.LastResult == null)
        {
            Vm.StatusText = "Нет результата для сохранения. Сначала выполните операцию.";
            return;
        }

        string suggestedName = Vm.IsEncryptMode ? "encrypted.bin" : "decrypted.dat";

        var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Сохранить результат",
            SuggestedFileName = suggestedName,
            FileTypeChoices = new[]
            {
                new FilePickerFileType("Все файлы") { Patterns = new[] { "*.*" } }
            }
        });

        if (file == null) return;

        try
        {
            var path = file.TryGetLocalPath()!;
            await File.WriteAllBytesAsync(path, Vm.LastResult);
            Vm.StatusText = $"Файл сохранён: {path}";
        }
        catch (Exception ex)
        {
            Vm.StatusText = "Ошибка сохранения: " + ex.Message;
        }
    }

    private int GetChunkSize()
    {
        if (!System.Numerics.BigInteger.TryParse(Vm.NText, out var n) || n == 0) return 4;
        int bytes = (int)Math.Ceiling(System.Numerics.BigInteger.Log(n, 256));
        if (bytes <= 1) return 1;
        if (bytes <= 2) return 2;
        if (bytes <= 4) return 4;
        return 8;
    }
}