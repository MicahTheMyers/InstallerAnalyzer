using System.Globalization;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;

namespace InstallerAnalyzer;

public sealed class ColorPickerWindow : Window
{
    public string SelectedColor { get; private set; } = "#3B82F6";
    private double _hue, _saturation, _value;
    private bool _updating;
    private readonly Slider _hueBar;
    private readonly Grid _square;
    private readonly Border _hueLayer, _preview;
    private readonly Ellipse _marker;
    private readonly TextBox _hex;
    private readonly TextBlock _rgb, _status;
    private readonly Button _apply;

    public ColorPickerWindow(Window owner, string initial)
    {
        Owner = owner; Title = "Custom color"; Width = 440; Height = 450;
        WindowStartupLocation = WindowStartupLocation.CenterOwner; ResizeMode = ResizeMode.NoResize;
        Resources.MergedDictionaries.Add(owner.Resources);
        Background = (Brush)owner.Resources["Card"]; Foreground = (Brush)owner.Resources["Text"];
        var panel = new StackPanel { Margin = new Thickness(22) }; Content = panel;
        var header = new Grid(); header.ColumnDefinitions.Add(new()); header.ColumnDefinitions.Add(new() { Width = GridLength.Auto }); header.ColumnDefinitions.Add(new());
        header.Children.Add(new TextBlock { Text = "HEX", Foreground = (Brush)owner.Resources["Muted"], VerticalAlignment = VerticalAlignment.Center });
        _hex = new TextBox { Width = 134, FontSize = 16, MaxLength = 7, TextAlignment = TextAlignment.Center,
            FontFamily = new FontFamily("Cascadia Mono, Consolas"), ToolTip = "Enter a six-digit hex color, such as #FF2A2A" };
        _hex.CaretBrush = Foreground;
        AutomationProperties.SetName(_hex, "Hex color, RRGGBB"); Grid.SetColumn(_hex, 1); header.Children.Add(_hex);
        _preview = new Border { Width = 32, Height = 32, CornerRadius = new CornerRadius(16), BorderThickness = new Thickness(1), BorderBrush = (Brush)owner.Resources["Border"], HorizontalAlignment = HorizontalAlignment.Right, ToolTip = "Selected color preview" };
        Grid.SetColumn(_preview, 2); header.Children.Add(_preview); panel.Children.Add(header);
        var area = new Grid { Height = 220, Margin = new Thickness(0, 14, 0, 10) };
        area.ColumnDefinitions.Add(new()); area.ColumnDefinitions.Add(new() { Width = new GridLength(42) });
        _square = new Grid { Focusable = true, Cursor = Cursors.Cross, Margin = new Thickness(0, 0, 14, 0), Background = Brushes.Transparent };
        AutomationProperties.SetName(_square, "Saturation and brightness color area");
        AutomationProperties.SetHelpText(_square, "Drag to choose a color. Arrow keys adjust saturation and brightness; Shift makes larger steps.");
        _hueLayer = new Border { CornerRadius = new CornerRadius(10) }; _square.Children.Add(_hueLayer);
        _square.Children.Add(new Border { CornerRadius = new CornerRadius(10), Background = new LinearGradientBrush(Colors.White, Colors.Transparent, new Point(0, .5), new Point(1, .5)) { ColorInterpolationMode = ColorInterpolationMode.SRgbLinearInterpolation }, IsHitTestVisible = false });
        _square.Children.Add(new Border { CornerRadius = new CornerRadius(10), Background = new LinearGradientBrush(Color.FromArgb(0, 0, 0, 0), Colors.Black, new Point(.5, 0), new Point(.5, 1)) { ColorInterpolationMode = ColorInterpolationMode.SRgbLinearInterpolation }, IsHitTestVisible = false });
        var markerCanvas = new Canvas { IsHitTestVisible = false, ClipToBounds = false };
        _marker = new Ellipse { Width = 18, Height = 18, Fill = Brushes.Transparent, Stroke = Brushes.White, StrokeThickness = 2,
            Effect = new System.Windows.Media.Effects.DropShadowEffect { Color = Colors.Black, ShadowDepth = 0, BlurRadius = 3, Opacity = .7 } };
        markerCanvas.Children.Add(_marker); _square.Children.Add(markerCanvas); area.Children.Add(_square);
        _hueBar = new Slider { Minimum = 0, Maximum = 360, Orientation = Orientation.Vertical, IsDirectionReversed = true,
            SmallChange = 1, LargeChange = 15, Width = 34, HorizontalAlignment = HorizontalAlignment.Center, Cursor = Cursors.Hand, ToolTip = "Hue" };
        AutomationProperties.SetName(_hueBar, "Hue");
        _hueBar.Template = (ControlTemplate)System.Windows.Markup.XamlReader.Parse("""
            <ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" TargetType="Slider">
              <Grid><Border CornerRadius="10" Margin="0,4,0,4"><Border.Background><LinearGradientBrush StartPoint="0,0" EndPoint="0,1"><GradientStop Color="#FF0000" Offset="0"/><GradientStop Color="#FFFF00" Offset="0.1666667"/><GradientStop Color="#00FF00" Offset="0.3333333"/><GradientStop Color="#00FFFF" Offset="0.5"/><GradientStop Color="#0000FF" Offset="0.6666667"/><GradientStop Color="#FF00FF" Offset="0.8333333"/><GradientStop Color="#FF0000" Offset="1"/></LinearGradientBrush></Border.Background></Border>
                <Track x:Name="PART_Track" Orientation="Vertical" IsDirectionReversed="{TemplateBinding IsDirectionReversed}" Minimum="{TemplateBinding Minimum}" Maximum="{TemplateBinding Maximum}" Value="{Binding Value,RelativeSource={RelativeSource TemplatedParent},Mode=TwoWay}">
                  <Track.DecreaseRepeatButton><RepeatButton Command="Slider.DecreaseLarge" Opacity="0" Focusable="False"/></Track.DecreaseRepeatButton>
                  <Track.Thumb><Thumb Height="8" Width="40"><Thumb.Template><ControlTemplate TargetType="Thumb"><Border Background="White" BorderBrush="#64748B" BorderThickness="1" CornerRadius="2"/></ControlTemplate></Thumb.Template></Thumb></Track.Thumb>
                  <Track.IncreaseRepeatButton><RepeatButton Command="Slider.IncreaseLarge" Opacity="0" Focusable="False"/></Track.IncreaseRepeatButton>
                </Track>
              </Grid>
            </ControlTemplate>
            """);
        Grid.SetColumn(_hueBar, 1); area.Children.Add(_hueBar); panel.Children.Add(area);
        _rgb = new TextBlock { Foreground = (Brush)owner.Resources["Muted"], HorizontalAlignment = HorizontalAlignment.Center, FontSize = 12 }; panel.Children.Add(_rgb);
        _status = new TextBlock { Height = 22, Margin = new Thickness(0, 4, 0, 5), Foreground = (Brush)owner.Resources["Text"], FontSize = 12 }; panel.Children.Add(_status);
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        buttons.Children.Add(new Button { Content = "Cancel", Padding = new Thickness(16, 6, 16, 6), IsCancel = true, Margin = new Thickness(0, 0, 8, 0) });
        _apply = new Button { Content = "Apply color", Padding = new Thickness(16, 6, 16, 6), IsDefault = true, Style = (Style)FindResource("PrimaryButton") };
        _apply.Click += (_, _) => { if (TryParseHex(_hex.Text, out _)) DialogResult = true; };
        buttons.Children.Add(_apply); panel.Children.Add(buttons);
        _square.MouseLeftButtonDown += (_, e) => { _square.Focus(); _square.CaptureMouse(); ChoosePoint(e.GetPosition(_square)); e.Handled = true; };
        _square.MouseMove += (_, e) => { if (_square.IsMouseCaptured && e.LeftButton == MouseButtonState.Pressed) ChoosePoint(e.GetPosition(_square)); };
        _square.MouseLeftButtonUp += (_, e) => { if (_square.IsMouseCaptured) { ChoosePoint(e.GetPosition(_square)); _square.ReleaseMouseCapture(); e.Handled = true; } };
        _square.SizeChanged += (_, _) => PositionMarker(); _square.KeyDown += SquareKeyDown;
        _hueBar.ValueChanged += (_, _) => { if (!_updating) { _hue = _hueBar.Value; RefreshColor(true); } };
        _hex.TextChanged += (_, _) =>
        {
            if (_updating) return;
            if (!TryParseHex(_hex.Text, out var color)) { _apply.IsEnabled = false; _status.Text = "Enter six hex digits, for example #FF2A2A."; return; }
            SetFromColor(color, false);
        };
        SetFromColor(TryParseHex(initial, out var start) ? start : Color.FromRgb(59, 130, 246), true);
    }
    private void ChoosePoint(Point point)
    {
        if (_square.ActualWidth <= 0 || _square.ActualHeight <= 0) return;
        _saturation = Math.Clamp(point.X / _square.ActualWidth, 0, 1); _value = 1 - Math.Clamp(point.Y / _square.ActualHeight, 0, 1); RefreshColor(true);
    }
    private void SquareKeyDown(object sender, KeyEventArgs e)
    {
        var step = Keyboard.Modifiers.HasFlag(ModifierKeys.Shift) ? .1 : .01;
        switch (e.Key)
        {
            case Key.Left: _saturation -= step; break;
            case Key.Right: _saturation += step; break;
            case Key.Up: _value += step; break;
            case Key.Down: _value -= step; break;
            case Key.Home: _saturation = 0; _value = 1; break;
            case Key.End: _value = 0; break;
            default: return;
        }
        _saturation = Math.Clamp(_saturation, 0, 1); _value = Math.Clamp(_value, 0, 1); e.Handled = true; RefreshColor(true);
    }
    private void SetFromColor(Color color, bool writeHex)
    {
        var hsv = ColorToHsv(color); if (hsv.Saturation > 0) _hue = hsv.Hue;
        _saturation = hsv.Saturation; _value = hsv.Value; RefreshColor(writeHex);
    }
    private void RefreshColor(bool writeHex)
    {
        _updating = true;
        try
        {
            var color = HsvToColor(_hue, _saturation, _value); SelectedColor = $"#{color.R:X2}{color.G:X2}{color.B:X2}";
            _preview.Background = new SolidColorBrush(color); _hueLayer.Background = new SolidColorBrush(HsvToColor(_hue, 1, 1));
            _hueBar.Value = _hue; _rgb.Text = $"R {color.R}     G {color.G}     B {color.B}";
            if (writeHex) _hex.Text = SelectedColor;
            _status.Text = ""; _apply.IsEnabled = true; PositionMarker();
        }
        finally { _updating = false; }
    }
    private void PositionMarker()
    {
        Canvas.SetLeft(_marker, _saturation * _square.ActualWidth - _marker.Width / 2); Canvas.SetTop(_marker, (1 - _value) * _square.ActualHeight - _marker.Height / 2);
    }
    internal static bool TryParseHex(string? text, out Color color)
    {
        color = Colors.Black; var value = (text ?? "").Trim();
        if (!Regex.IsMatch(value, "^#?[0-9a-fA-F]{6}$")) return false;
        value = value.TrimStart('#');
        var number = uint.Parse(value, NumberStyles.HexNumber, CultureInfo.InvariantCulture); color = Color.FromRgb((byte)(number >> 16), (byte)(number >> 8), (byte)number); return true;
    }
    internal static (double Hue, double Saturation, double Value) ColorToHsv(Color color)
    {
        var r = color.R / 255d; var g = color.G / 255d; var b = color.B / 255d; var max = Math.Max(r, Math.Max(g, b)); var min = Math.Min(r, Math.Min(g, b)); var delta = max - min;
        var hue = delta == 0 ? 0 : max == r ? 60 * (((g - b) / delta) % 6) : max == g ? 60 * ((b - r) / delta + 2) : 60 * ((r - g) / delta + 4);
        if (hue < 0) hue += 360; return (hue, max == 0 ? 0 : delta / max, max);
    }
    internal static Color HsvToColor(double hue, double saturation, double value)
    {
        if (!double.IsFinite(hue) || !double.IsFinite(saturation) || !double.IsFinite(value)) throw new ArgumentException("Color components must be finite.");
        hue = (hue % 360 + 360) % 360; saturation = Math.Clamp(saturation, 0, 1); value = Math.Clamp(value, 0, 1);
        var chroma = value * saturation; var x = chroma * (1 - Math.Abs((hue / 60) % 2 - 1)); var m = value - chroma;
        var (r, g, b) = hue switch { < 60 => (chroma, x, 0d), < 120 => (x, chroma, 0d), < 180 => (0d, chroma, x), < 240 => (0d, x, chroma), < 300 => (x, 0d, chroma), _ => (chroma, 0d, x) };
        return Color.FromRgb((byte)Math.Round((r + m) * 255), (byte)Math.Round((g + m) * 255), (byte)Math.Round((b + m) * 255));
    }
}
