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

    // ── Открыть файл ─────────────────────────────────────────────────────────
    private async void OpenFileClick(object? sender, RoutedEventArgs e)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Открыть файл",
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
            Vm.StatusText = "Ошибка открытия: " + ex.Message;
        }
    }

    // ── Выполнить ────────────────────────────────────────────────────────────
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
                    // Показываем первые 64 числа из зашифрованного текста
                    Vm.ResultPreview = MainWindowViewModel.BuildEncryptedTextPreview(result, 64);
                    Vm.StatusText = $"Готово. Исходный: {_sourceBytes.Length} байт → " +
                                    $"Зашифрованный: {result.Length} байт (текст с числами).";
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
                    Vm.StatusText = $"Готово. Расшифровано {result.Length} байт.";
                }
            }
        }
        catch (OperationCanceledException)
        {
            Vm.StatusText = "Отменено.";
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

    // ── Сохранить результат ──────────────────────────────────────────────────
    private async void SaveFileClick(object? sender, RoutedEventArgs e)
    {
        if (Vm.LastResult == null)
        {
            Vm.StatusText = "Нет результата для сохранения.";
            return;
        }

        // При шифровании предлагаем .bin (но это текстовый файл с числами)
        // При дешифровании — оригинальное расширение пользователь выберет сам
        string suggested = Vm.IsEncryptMode ? "encrypted.bin" : "decrypted_file";

        var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Сохранить результат",
            SuggestedFileName = suggested,
            FileTypeChoices = new[] { new FilePickerFileType("Все файлы") { Patterns = new[] { "*.*" } } }
        });
        if (file == null) return;

        try
        {
            await File.WriteAllBytesAsync(file.TryGetLocalPath()!, Vm.LastResult);
            Vm.StatusText = $"Сохранено: {file.TryGetLocalPath()}";
        }
        catch (Exception ex)
        {
            Vm.StatusText = "Ошибка сохранения: " + ex.Message;
        }
    }
}