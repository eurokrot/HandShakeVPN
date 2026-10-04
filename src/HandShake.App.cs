using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Input;
using System.Windows.Shapes;
using System.Windows.Threading;
using Forms = System.Windows.Forms;

namespace HandShake
{
    public sealed class DesktopApp
    {
        private Window window;
        private Window mapWindow;
        private double mapZoom = 1;
        private bool testing;
        private Forms.NotifyIcon tray;
        private System.Drawing.Icon trayIcon;
        private Forms.ToolStripMenuItem trayOpenItem;
        private Forms.ToolStripMenuItem trayDisconnectItem;
        private Forms.ToolStripMenuItem trayNodeItem;
        private Forms.ToolStripMenuItem trayCloseItem;
        private bool exit;
        private bool loadingSettings;
        private readonly ConnectionController connection = new ConnectionController();
        private IList<Node> nodes;
        private Node mapNode;
        private DispatcherTimer frameTimer;
        private DispatcherTimer catalogTimer;
        private DispatcherTimer vpnHealthTimer;
        private bool vpnHealthBusy;
        private bool vpnDisconnectBusy;
        private bool vpnNeedsDisconnect;
        private int vpnCommandGeneration;
        private int frame;
        private ConnectionState renderedState = ConnectionState.Disconnected;
        private bool english;
        private bool menuClosing;
        private int mapSearchGeneration;
        private readonly List<Ellipse> mapSearchDots = new List<Ellipse>();
        private readonly Dictionary<string, Point> mapNodePoints = new Dictionary<string, Point>();
        private string accent = "#2889DB";
        private readonly string settingsPath = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "HandShake", "Preview", "appearance.txt");
        private readonly string[] startupArguments;
        private ClientConfiguration clientConfiguration;
        private IControlPlaneClient controlPlane;
        private Node selfLocation;
        private IServiceBridge serviceBridge;
        private DeviceIdentity deviceIdentity;
        private DeviceCredential credential;
        private DeviceCredentialStore credentialStore;
        private CancellationTokenSource sessionCancellation;
        private SessionLease preparedSession;
        private string connectionError;
        private string configurationError;
        private string catalogError;
        private string vpnTrafficSafety;
        private string nodeServiceState = "unavailable";
        private string nodeServiceError;
        private bool nodeParticipationBusy;
        private readonly SemaphoreSlim nodeBootstrapGate = new SemaphoreSlim(1, 1);
        private DateTime nextUpdateCheckUtc = DateTime.MinValue;
        private string selectedHomeNodeId;
        private bool rebindingHome;
        private readonly SemaphoreSlim diagnosticUploadGate = new SemaphoreSlim(1, 1);
        private readonly object diagnosticThrottleSync = new object();
        private readonly Dictionary<string, DateTime> diagnosticNextAllowedUtc =
            new Dictionary<string, DateTime>(StringComparer.Ordinal);

        public DesktopApp() : this(new string[0]) { }
        private DesktopApp(string[] args) { startupArguments = args ?? new string[0]; }

        [STAThread]
        public static int Main(string[] args)
        {
            try
            {
                if (args.Contains("--self-test")) return SmokeTest();
                using (var instance = new ApplicationInstanceGuard(System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "HandShake", "ControlPlane")))
                {
                    if (!instance.Acquired) { instance.RequestOpen(); return 0; }
                    var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
                    var desktop = new DesktopApp(args);
                    desktop.Initialize();
                    var restoreTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
                    restoreTimer.Tick += delegate { if (instance.ConsumeOpenRequest()) desktop.Restore(); };
                    restoreTimer.Start();
                    try { app.Run(desktop.window); }
                    finally { restoreTimer.Stop(); }
                }
                return 0;
            }
            catch (Exception ex)
            {
                if (args.Contains("--self-test")) { File.WriteAllText(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "self-test-error.txt"), ex.ToString()); return 1; }
                MessageBox.Show("Не удалось запустить приложение: " + ex.Message, "HandShake VPN");
                return 1;
            }
        }

        private static Window LoadWindow(string name)
        {
            using (var stream = typeof(DesktopApp).Assembly.GetManifestResourceStream(name))
                return (Window)XamlReader.Load(stream);
        }

        private static void Pump(int milliseconds)
        {
            var loop = new DispatcherFrame();
            var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(milliseconds) };
            timer.Tick += delegate { timer.Stop(); loop.Continue = false; };
            timer.Start();
            Dispatcher.PushFrame(loop);
        }

        private static int SmokeTest()
        {
            new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
            System.Threading.SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(Dispatcher.CurrentDispatcher));
            var d = new DesktopApp { testing = true };
            d.Initialize(false);
            d.window.Show();
            d.window.UpdateLayout();
            if (d.window.ActualWidth != 380 || d.window.ActualHeight != 650 || d.Get<Canvas>("WorldMap").Children.Count < 170) throw new Exception("Window/map not built");
            if (d.Get<Image>("BrandLogo").Source == null) throw new Exception("Brand logo was not loaded");
            d.ShowActivation();
            d.window.UpdateLayout();
            if (d.Get<Button>("ActivationRestoreNetwork").Visibility != Visibility.Visible)
                throw new Exception("Network recovery must remain available without activation");
            if (d.Get<Grid>("ActivationOverlay").Visibility != Visibility.Visible || d.Get<Button>("ContinueDemo").Visibility != Visibility.Visible || d.Get<Button>("ActivateButton").Visibility != Visibility.Collapsed)
                throw new Exception("Demo activation boundary missing");
            SavePreview(d.window, "preview-activation.png");
            d.Get<Button>("ContinueDemo").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            if (d.Get<Grid>("ActivationOverlay").Visibility != Visibility.Collapsed) throw new Exception("Demo activation close failed");
            d.clientConfiguration = ClientConfiguration.Create(ClientEnvironmentKind.Test, "http://127.0.0.1", true);
            d.nodes = new List<Node>();
            d.RebindCatalog();
            d.ShowActivation();
            d.window.UpdateLayout();
            if (d.Get<Button>("ActivateButton").Visibility != Visibility.Visible || d.Get<Button>("CloseActivation").Visibility != Visibility.Collapsed || !d.Get<TextBlock>("ActivationModeText").Text.Contains("HTTP"))
                throw new Exception("Insecure test activation is not labelled");
            SavePreview(d.window, "preview-activation-test.png");
            d.clientConfiguration = ClientConfiguration.Demo();
            d.nodes = new DemoNodeCatalog().GetNodes();
            d.RebindCatalog();
            Pump(40);
            var homeLocations = d.Get<ComboBox>("HomeLocationPicker");
            if (homeLocations.Items.Count != d.nodes.Count + 1 || ((Node)homeLocations.SelectedItem).Id != null)
                throw new Exception("Automatic location choice missing");
            homeLocations.SelectedItem = d.nodes.First(n => n.Id == "nl");
            d.RebindCatalog();
            if (d.selectedHomeNodeId != "nl" || ((Node)homeLocations.SelectedItem).Id != "nl")
                throw new Exception("Location choice lost during catalog refresh");
            if (!((Node)homeLocations.SelectedItem).DisplayLabel.Contains("ms") || ((Node)homeLocations.SelectedItem).FlagImage == null)
                throw new Exception("Location latency or country flag missing");
            homeLocations.SelectedIndex = 0;
            Pump(40);
            d.Get<Grid>("ActivationOverlay").Visibility = Visibility.Collapsed;
            d.Get<Grid>("HomeContent").IsEnabled = true;
            d.Get<Button>("PinWindow").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            if (!d.window.Topmost) throw new Exception("Pin failed");
            d.Get<Button>("PinWindow").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            if (d.window.Topmost) throw new Exception("Unpin failed");
            SavePreview(d.window, "preview-home.png");
            d.Get<Button>("MenuButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            if (d.Get<Grid>("MenuOverlay").Visibility != Visibility.Visible) throw new Exception("Menu failed");
            Pump(380);
            if (Math.Abs(((TranslateTransform)d.Get<Border>("MenuPanel").RenderTransform).X) > 1) throw new Exception("Menu slide failed");
            d.window.UpdateLayout();
            SavePreview(d.window, "preview-menu.png");
            d.Get<Button>("LanguageButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            if (!d.english || d.Get<Button>("ConnectButton").Content.ToString() != "Connect") throw new Exception("English localization failed");
            d.window.UpdateLayout();
            SavePreview(d.window, "preview-english.png");
            d.Get<Button>("LanguageButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            d.Get<Button>("CloseMenu").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            Pump(280);
            if (d.Get<Grid>("MenuOverlay").Visibility != Visibility.Collapsed) throw new Exception("Menu close animation failed");
            d.Get<Button>("MenuButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            Pump(350);
            d.Get<Button>("NavSettings").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            d.window.UpdateLayout();
            if (Application.Current.Windows.Count != 2 || d.Get<Grid>("SettingsOverlay").Visibility != Visibility.Visible) throw new Exception("Settings must remain inside main window");
            SavePreview(d.window, "preview-settings.png");
            d.Get<Button>("CloseSettings").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            d.Get<Button>("CircleConnect").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            if (d.connection.State != ConnectionState.Connecting || d.Get<Ellipse>("ConnectionRing").Visibility != Visibility.Visible) throw new Exception("Circle connect failed");
            Pump(2600);
            if (d.connection.State != ConnectionState.Connected) throw new Exception("Demo connect failed");
            var activeExit = d.connection.Selected;
            d.preparedSession = new SessionLease { hops = new List<SessionHop> {
                new SessionHop { nodeId = activeExit.Id, ip = "203.0.113.45" } } };
            d.RefreshMapConnectionDetails();
            if (d.ConnectedExitIp(activeExit) != "203.0.113.45" || !d.Details(activeExit).Contains("203.0.113.45") ||
                d.nodes.Where(n => n.Id != activeExit.Id).Any(n => d.ConnectedExitIp(n) != null))
                throw new Exception("Connected map must reveal only the active exit address");
            d.window.UpdateLayout();
            var translate = (TranslateTransform)d.Get<TextBlock>("Face").RenderTransform;
            if (Math.Abs(translate.Y) > .1) throw new Exception("Happy face did not hold");
            SavePreview(d.window, "preview-connected.png");
            int hopCount = 0;
            int greenHops = 0;
            bool airborne = false;
            bool greenVisible = false;
            var samples = new List<double>();
            var greenSamples = new List<double>();
            for (int step = 0; step < 30; step++)
            {
                Pump(80);
                samples.Add(translate.Y);
                greenSamples.Add(d.Get<Ellipse>("SuccessFill").Opacity);
                bool nowAirborne = translate.Y < -1;
                if (nowAirborne && !airborne) hopCount++;
                bool nowGreen = d.Get<Ellipse>("SuccessFill").Opacity > .5;
                if (nowGreen && !greenVisible) greenHops++;
                if (nowAirborne && hopCount == 1) SavePreview(d.window, "preview-hop.png");
                airborne = nowAirborne;
                greenVisible = nowGreen;
            }
            if (SystemParameters.ClientAreaAnimation && hopCount != 2) throw new Exception("Expected two hops: " + String.Join(",", samples));
            if (SystemParameters.ClientAreaAnimation && greenHops != 2) throw new Exception("Success circle was not green for both hops: " + String.Join(",", greenSamples));
            if (Math.Abs(translate.Y) > .1) throw new Exception("Hop did not settle");
            d.Get<Button>("CircleConnect").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            if (d.connection.State != ConnectionState.Disconnected) throw new Exception("Circle disconnect failed");
            if (d.ConnectedExitIp(activeExit) != null || d.Details(activeExit).Contains("203.0.113.45"))
                throw new Exception("Disconnected map retained the previous exit address");
            d.Get<Button>("CircleConnect").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            d.Get<Button>("CircleConnect").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            Pump(2600);
            if (d.connection.State != ConnectionState.Disconnected) throw new Exception("Cancellation reconnects");
            d.ShowPage("Map");
            d.mapWindow.UpdateLayout();
            var scroll = d.Get<ScrollViewer>("MapScroll");
            double width = d.Get<Viewbox>("MapView").Width;
            scroll.RaiseEvent(new MouseWheelEventArgs(Mouse.PrimaryDevice, Environment.TickCount, 120) { RoutedEvent = Mouse.PreviewMouseWheelEvent });
            if (d.Get<Viewbox>("MapView").Width <= width) throw new Exception("Wheel zoom failed");
            d.Get<Button>("ZoomReset").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            d.Get<ComboBox>("LocationPicker").SelectedIndex = 2;
            if (d.mapNode.Id != "fi") throw new Exception("Manual selection failed");
            d.Get<ComboBox>("LocationPicker").SelectedIndex = 0;
            d.mapWindow.UpdateLayout();
            SavePreview(d.mapWindow, "preview-map.png");
            var marker = d.Get<Canvas>("WorldMap").Children.OfType<Grid>().First();
            var tip = marker.ToolTip as ToolTip;
            if (tip == null || ((StackPanel)tip.Content).Children.Count != 4 ||
                ((StackPanel)tip.Content).Children.OfType<TextBlock>().Any(t => t.Text.StartsWith("IP ", StringComparison.Ordinal)))
                throw new Exception("Disconnected node hover card exposes an address or is incomplete");
            tip.PlacementTarget = marker;
            tip.IsOpen = true;
            Pump(180);
            tip.UpdateLayout();
            SaveElementPreview((FrameworkElement)tip.Content, tip.Background, "preview-node-card.png", 14);
            tip.IsOpen = false;
            d.Get<Button>("MapConnect").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            Pump(220);
            if (!d.mapSearchDots.Any(dot => dot.Visibility == Visibility.Visible)) throw new Exception("Map selection animation missing");
            SavePreview(d.mapWindow, "preview-map-search.png");
            Pump(1750);
            if (d.connection.State != ConnectionState.Connecting || d.mapWindow.IsVisible) throw new Exception("Map selection did not start connection");
            d.Get<Button>("CircleConnect").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            d.ShowPage("Map");
            d.mapWindow.Close();
            d.ShowPage("Map");
            if (!d.mapWindow.IsVisible) throw new Exception("Map reopen failed");
            d.mapWindow.Hide();
            d.ShowPage("Settings");
            foreach (string font in new[] { "Segoe UI", "Arial", "Calibri", "Verdana", "Consolas" })
            {
                d.Get<ComboBox>("FontPicker").SelectedItem = font;
                d.window.UpdateLayout();
                var circle = d.Get<Button>("CircleConnect");
                if (circle.ActualHeight != circle.ActualWidth) throw new Exception("Status circle stretched");
            }
            d.Get<ComboBox>("FontPicker").SelectedIndex = 0;
            d.HideOverlay();
            Task backgroundCatalogUpdate = Task.Run(async delegate {
                await d.ApplyCatalogOnUiAsync(new DemoNodeCatalog().GetNodes());
            });
            DateTime catalogDeadline = DateTime.UtcNow.AddSeconds(5);
            while (!backgroundCatalogUpdate.IsCompleted && DateTime.UtcNow < catalogDeadline) Pump(20);
            if (!backgroundCatalogUpdate.IsCompleted) throw new Exception("Cross-thread catalog update timed out");
            backgroundCatalogUpdate.GetAwaiter().GetResult();
            if (d.Get<ComboBox>("LocationPicker").Items.Count == 0) throw new Exception("Cross-thread catalog update failed");
            d.connection.Disconnect();
            d.FailClientInitialization("Injected missing configuration");
            d.RebindCatalog(); d.ShowActivation(); d.ToggleConnection();
            if (d.nodes.Count != 0 || d.clientConfiguration.Environment == ClientEnvironmentKind.Demo ||
                d.Get<Button>("ContinueDemo").Visibility != Visibility.Collapsed ||
                d.Get<Button>("ActivateButton").IsEnabled || d.CanCloseActivation() || d.connection.State == ConnectionState.Connected)
                throw new Exception("Startup failure exposed a demo catalog or fake connection");
            d.Get<Button>("ContinueDemo").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            if (d.Get<Grid>("ActivationOverlay").Visibility != Visibility.Visible)
                throw new Exception("Startup failure activation gate was bypassed");
            File.WriteAllText(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "self-test-result.txt"), "PASS: activation boundary, richer waves, pin/unpin, animated menu, RU/EN, inline settings, spinner, two green success hops, wheel zoom, compact node card, animated map selection, map reopening, font switching, UI-thread catalog marshaling.");
            d.exit = true;
            d.window.Close();
            return 0;
        }

        private static void SaveElementPreview(FrameworkElement content, Brush background, string filename, int padding)
        {
            var visual = new DrawingVisual();
            using (var dc = visual.RenderOpen())
            {
                dc.DrawRectangle(background, null, new Rect(0, 0, content.ActualWidth + padding * 2, content.ActualHeight + padding * 2));
                dc.DrawRectangle(new VisualBrush(content), null, new Rect(padding, padding, content.ActualWidth, content.ActualHeight));
            }
            var image = new System.Windows.Media.Imaging.RenderTargetBitmap((int)Math.Ceiling(content.ActualWidth) + padding * 2, (int)Math.Ceiling(content.ActualHeight) + padding * 2, 96, 96, PixelFormats.Pbgra32);
            image.Render(visual);
            var encoder = new System.Windows.Media.Imaging.PngBitmapEncoder();
            encoder.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(image));
            using (var stream = File.Create(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, filename))) encoder.Save(stream);
        }

        private static void SavePreview(Window target, string filename)
        {
            var content = (FrameworkElement)target.Content;
            var bounds = new Rect(0, 0, content.ActualWidth + content.Margin.Left + content.Margin.Right, content.ActualHeight + content.Margin.Top + content.Margin.Bottom);
            var visual = new DrawingVisual();
            using (var dc = visual.RenderOpen())
            {
                dc.DrawRectangle(target.Background, null, bounds);
            }
            var image = new System.Windows.Media.Imaging.RenderTargetBitmap((int)Math.Ceiling(bounds.Width), (int)Math.Ceiling(bounds.Height), 96, 96, PixelFormats.Pbgra32);
            image.Render(visual);
            image.Render(content);
            var encoder = new System.Windows.Media.Imaging.PngBitmapEncoder();
            encoder.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(image));
            using (var stream = File.Create(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, filename))) encoder.Save(stream);
        }

        private T Get<T>(string name) where T : class { return (window.FindName(name) ?? mapWindow.FindName(name)) as T; }
        private void Click(string name, Action action) { Get<Button>(name).Click += delegate { action(); }; }

        private void Initialize(bool createTray = true)
        {
            window = LoadWindow("MainWindow.xaml");
            mapWindow = LoadWindow("MapWindow.xaml");
            LoadBrandLogo();
            SetupClientRuntime();
            window.Loaded += async delegate {
                mapWindow.Owner = window;
                if (!testing && HasActiveCredential() && clientConfiguration.HasControlPlane)
                {
                    await RefreshCredentialPolicyAsync();
                    await BootstrapNodeServiceAsync();
                    RefreshCatalogFromServer();
                    await CheckForUpdateAsync();
                }
                if (!testing) await RefreshServiceStatusesAsync();
                if (!testing) await RefreshVpnHealthAsync();
            };
            foreach (var child in new[] { mapWindow })
                child.Closing += delegate(object sender, System.ComponentModel.CancelEventArgs e) {
                    if (sender == mapWindow) CancelMapSearch();
                    if (!exit) { e.Cancel = true; ((Window)sender).Hide(); }
                };
            Click("NavMap", delegate { ShowPage("Map"); });
            Click("NavSettings", delegate { ShowPage("Settings"); });
            Click("NavActivation", ShowActivation);
            Click("RestoreNetwork", RestoreOrdinaryNetwork);
            Click("ActivationRestoreNetwork", RestoreOrdinaryNetwork);
            Click("ConnectButton", ToggleConnection);
            Click("CircleConnect", ToggleConnection);
            Click("MenuButton", delegate { ShowOverlay("Menu"); });
            Click("CloseMenu", HideOverlay);
            Click("CloseSettings", HideOverlay);
            Click("LanguageButton", delegate { english = !english; ApplyLanguage(); SaveSettings(); });
            Click("PinWindow", TogglePinned);
            Click("MenuHide", delegate { window.Close(); });
            Click("CloseWindow", delegate { window.Close(); });
            Click("MinimizeWindow", delegate { window.WindowState = WindowState.Minimized; });
            Click("MapClose", delegate { CancelMapSearch(); mapWindow.Close(); });
            Get<Border>("MenuBackdrop").MouseLeftButtonDown += delegate { HideOverlay(); };
            Get<Border>("SettingsBackdrop").MouseLeftButtonDown += delegate { HideOverlay(); };
            Get<Grid>("TitleBar").MouseLeftButtonDown += delegate(object sender, MouseButtonEventArgs e) {
                if (e.LeftButton == MouseButtonState.Pressed) window.DragMove();
            };
            Get<Grid>("MapTitleBar").MouseLeftButtonDown += delegate(object sender, MouseButtonEventArgs e) {
                if (e.LeftButton == MouseButtonState.Pressed) mapWindow.DragMove();
            };
            window.PreviewKeyDown += delegate(object sender, KeyEventArgs e) {
                if (e.Key == Key.Escape) { HideOverlay(); e.Handled = true; }
            };
            Get<ScrollViewer>("MapScroll").PreviewMouseWheel += delegate(object sender, MouseWheelEventArgs e) {
                ZoomAt(Math.Pow(1.2, e.Delta / 120.0), e.GetPosition(Get<ScrollViewer>("MapScroll")));
                e.Handled = true;
            };
            Get<ComboBox>("HomeLocationPicker").SelectionChanged += delegate {
                if (rebindingHome) return;
                var choice = Get<ComboBox>("HomeLocationPicker").SelectedItem as Node;
                selectedHomeNodeId = choice == null ? null : choice.Id;
                RefreshCatalog();
            };
            Get<ComboBox>("LocationPicker").ItemsSource = nodes;
            Get<ComboBox>("LocationPicker").SelectionChanged += delegate {
                var node = Get<ComboBox>("LocationPicker").SelectedItem as Node;
                if (node != null) SelectMapNode(node);
            };
            Get<ComboBox>("LocationPicker").SelectedIndex = 0;
            Click("MapConnect", BeginMapConnection);
            Click("ZoomIn", delegate { SetMapZoom(mapZoom * 1.5); });
            Click("ZoomOut", delegate { SetMapZoom(mapZoom / 1.5); });
            Click("ZoomReset", delegate { SetMapZoom(1); });
            Click("ActivateButton", Activate);
            Click("ContinueDemo", delegate { if (!testing || clientConfiguration.Environment != ClientEnvironmentKind.Demo) return; Get<Grid>("ActivationOverlay").Visibility = Visibility.Collapsed; Get<Grid>("HomeContent").IsEnabled = true; });
            Click("CloseActivation", delegate { if (CanCloseActivation()) { Get<Grid>("ActivationOverlay").Visibility = Visibility.Collapsed; Get<Grid>("HomeContent").IsEnabled = true; } });
            Get<TextBox>("ActivationKey").KeyDown += delegate(object sender, KeyEventArgs e) {
                if (e.Key == Key.Enter && Get<Button>("ActivateButton").IsEnabled) { Activate(); e.Handled = true; }
            };
            Get<CheckBox>("NodeParticipationToggle").Click += async delegate {
                if (!loadingSettings)
                    await SetNodeParticipationAsync(Get<CheckBox>("NodeParticipationToggle").IsChecked == true);
            };
            mapWindow.SizeChanged += delegate { SetMapZoom(mapZoom); };
            Get<ScrollViewer>("MapScroll").SizeChanged += delegate { SetMapZoom(mapZoom); };
            SetupSettings();
            DrawMap();
            SelectMapNode(ConnectionController.Fastest(nodes));
            ApplyLanguage();
            RefreshCatalog();
            RenderConnection();
            InitializeActivationUi();
            if (SystemParameters.ClientAreaAnimation) StartWaveAnimations();
            if (createTray)
            {
                SetupTray();
                frameTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(130) };
                frameTimer.Tick += delegate {
                    if (connection.State == ConnectionState.Connecting)
                        Get<TextBlock>("Face").Text = new[] { "|", "/", "-", "\\" }[frame++ % 4];
                };
                frameTimer.Start();
                catalogTimer = new DispatcherTimer { Interval = TimeSpan.FromMinutes(1) };
                catalogTimer.Tick += async delegate {
                    if (HasActiveCredential())
                    {
                        await RefreshCredentialPolicyAsync();
                        await BootstrapNodeServiceAsync();
                        RefreshCatalogFromServer();
                        await CheckForUpdateAsync();
                    }
                    else RefreshCatalog();
                    await RefreshServiceStatusesAsync();
                };
                catalogTimer.Start();
                vpnHealthTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
                vpnHealthTimer.Tick += async delegate { await RefreshVpnHealthAsync(); };
                vpnHealthTimer.Start();
            }
            window.Closing += delegate(object sender, System.ComponentModel.CancelEventArgs e) {
                if (!exit && tray != null) { e.Cancel = true; mapWindow.Hide(); HideOverlay(); window.Hide(); }
            };
            window.Closed += delegate {
                if (frameTimer != null) frameTimer.Stop();
                if (catalogTimer != null) catalogTimer.Stop();
                if (vpnHealthTimer != null) vpnHealthTimer.Stop();
                if (sessionCancellation != null) sessionCancellation.Cancel();
                if (controlPlane != null) controlPlane.Dispose();
                if (serviceBridge != null) serviceBridge.Dispose();
                if (tray != null) tray.Dispose();
                if (trayIcon != null) trayIcon.Dispose();
                Application.Current.Shutdown();
            };
        }

        private void SetupTray()
        {
            trayIcon = System.Drawing.Icon.ExtractAssociatedIcon(System.Reflection.Assembly.GetExecutingAssembly().Location);
            tray = new Forms.NotifyIcon { Icon = trayIcon ?? System.Drawing.SystemIcons.Application, Text = "HandShake VPN · демо", Visible = true };
            var menu = new Forms.ContextMenuStrip();
            trayOpenItem = new Forms.ToolStripMenuItem("Открыть HandShake VPN", null, delegate { Restore(); });
            trayDisconnectItem = new Forms.ToolStripMenuItem("Отключить демо-подключение", null, delegate { DisconnectPreparedSession(); });
            menu.Items.Add(trayOpenItem);
            menu.Items.Add(trayDisconnectItem);
            menu.Items.Add(new Forms.ToolStripSeparator());
            trayNodeItem = new Forms.ToolStripMenuItem("Node Service: не установлена") { Enabled = false };
            trayCloseItem = new Forms.ToolStripMenuItem("Закрыть интерфейс", null, delegate { exit = true; window.Close(); });
            menu.Items.Add(trayNodeItem);
            menu.Items.Add(trayCloseItem);
            tray.ContextMenuStrip = menu;
            tray.DoubleClick += delegate { Restore(); };
            ApplyTrayLanguage();
        }

        private void LoadBrandLogo()
        {
            using (Stream stream = typeof(DesktopApp).Assembly.GetManifestResourceStream("handshake.ico"))
            {
                if (stream == null) throw new InvalidDataException("Embedded HandShake logo is missing.");
                var decoder = System.Windows.Media.Imaging.BitmapDecoder.Create(
                    stream,
                    System.Windows.Media.Imaging.BitmapCreateOptions.PreservePixelFormat,
                    System.Windows.Media.Imaging.BitmapCacheOption.OnLoad);
                var frame = decoder.Frames
                    .OrderByDescending(item => item.PixelWidth * item.PixelHeight)
                    .FirstOrDefault();
                if (frame == null) throw new InvalidDataException("Embedded HandShake logo has no image frames.");
                if (frame.CanFreeze) frame.Freeze();
                Get<Image>("BrandLogo").Source = frame;
            }
        }

        private void SetupClientRuntime()
        {
            string localRoot = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "HandShake", "ControlPlane");
            var protector = new DpapiSecretProtector();
            credentialStore = new DeviceCredentialStore(System.IO.Path.Combine(localRoot, "device-token.bin"), protector);
            try
            {
                clientConfiguration = testing ? ClientConfiguration.Demo() : ClientConfiguration.Load(startupArguments);
                if (testing)
                    deviceIdentity = new DeviceIdentity(DeviceIdentityProvider.Hash("handshake-ui-self-test"), "test-override-sha256", false);
                else
                    deviceIdentity = new DeviceIdentityProvider(
                        new WindowsSystemDiskAnchorReader(false)).Get();
                nodes = clientConfiguration.Environment == ClientEnvironmentKind.Demo
                    ? new DemoNodeCatalog().GetNodes() : (IList<Node>)new List<Node>();
                if (clientConfiguration.HasControlPlane)
                    controlPlane = new HttpControlPlaneClient(clientConfiguration.ApiBaseUri);
                if (!testing)
                    serviceBridge = new NamedPipeServiceBridge(
                        ServiceProvisioningPolicy.AllowExperimentalFirewallLab(clientConfiguration));
                DeviceCredential loaded;
                if (!testing && credentialStore.TryLoad(out loaded))
                {
                    if (loaded.IsUsable && String.Equals(loaded.FingerprintHash, deviceIdentity.Id, StringComparison.Ordinal)) credential = loaded;
                    else credentialStore.Clear();
                }
            }
            catch (ConfigurationException ex)
            {
                FailClientInitialization(ex.Message);
            }
            catch (DeviceIdentityUnavailableException ex)
            {
                FailClientInitialization(ex.Message);
            }
            catch (Exception ex)
            {
                if (!(ex is IOException) && !(ex is UnauthorizedAccessException) && !(ex is System.Security.Cryptography.CryptographicException)) throw;
                FailClientInitialization("Device identity storage is unavailable.");
            }
        }

        private void FailClientInitialization(string message)
        {
            configurationError = message;
            clientConfiguration = ClientConfiguration.Unavailable();
            deviceIdentity = new DeviceIdentity(String.Empty, "unavailable", false);
            credential = null; selfLocation = null;
            nodes = new List<Node>();
            if (controlPlane != null) { controlPlane.Dispose(); controlPlane = null; }
            if (serviceBridge != null) { serviceBridge.Dispose(); serviceBridge = null; }
        }

        private async void ReportDiagnostic(string code)
        {
            if (testing || controlPlane == null || !HasActiveCredential()) return;
            if (!diagnosticUploadGate.Wait(0)) return;
            bool shouldSend = false;
            string token = credential.DeviceToken;
            IControlPlaneClient client = controlPlane;
            try
            {
                lock (diagnosticThrottleSync)
                {
                    DateTime nextAllowed;
                    DateTime now = DateTime.UtcNow;
                    if (!diagnosticNextAllowedUtc.TryGetValue(code, out nextAllowed) || now >= nextAllowed)
                    {
                        diagnosticNextAllowedUtc[code] = now.AddMinutes(5);
                        shouldSend = true;
                    }
                }
                if (!shouldSend) return;
                DiagnosticEventRequest diagnostic = DiagnosticEventFactory.Create(code);
                using (var timeout = new CancellationTokenSource())
                {
                    timeout.CancelAfter(TimeSpan.FromSeconds(5));
                    await client.ReportDiagnosticAsync(token, diagnostic, timeout.Token);
                }
            }
            catch (Exception)
            {
                // Diagnostics are best effort and must never affect VPN or Node Service behavior.
            }
            finally
            {
                diagnosticUploadGate.Release();
            }
        }

        private bool HasActiveCredential()
        {
            return credential != null && credential.IsUsable && deviceIdentity != null &&
                String.Equals(credential.FingerprintHash, deviceIdentity.Id, StringComparison.Ordinal);
        }

        private async Task RefreshCredentialPolicyAsync()
        {
            if (controlPlane == null || !HasActiveCredential()) return;
            try
            {
                credential = await controlPlane.RefreshCredentialPolicyAsync(credential, CancellationToken.None);
                credentialStore.Save(credential);
            }
            catch (ControlPlaneException)
            {
                // Keep the current usable credential when the policy service is temporarily unavailable.
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            catch (System.Security.Cryptography.CryptographicException) { }
        }

        private Task CheckForUpdateAsync()
        {
            // The independently running Node Service owns download and installation.
            // Only a confirmed installed release is shown, once per user profile.
            if (testing || DateTime.UtcNow < nextUpdateCheckUtc) return Task.FromResult(true);
            nextUpdateCheckUtc = DateTime.UtcNow.AddMinutes(1);
            try
            {
                string installed = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "update-installed.json");
                if (!File.Exists(installed)) return Task.FromResult(true);
                var record = new System.Web.Script.Serialization.JavaScriptSerializer().Deserialize<Dictionary<string, object>>(File.ReadAllText(installed));
                object versionValue;
                string version = record != null && record.TryGetValue("version", out versionValue) ? Convert.ToString(versionValue) : null;
                if (!String.Equals(version, HandShake.Release.ProductRelease.Version, StringComparison.Ordinal)) return Task.FromResult(true);
                string seen = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "HandShake", "last-update-notice.txt");
                if (File.Exists(seen) && File.ReadAllText(seen) == version) return Task.FromResult(true);
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(seen));
                File.WriteAllText(seen, version);
                MessageBox.Show(window, english ? "Update installed: " + version : "Обновление установлено: " + version,
                    "HandShake VPN", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            catch (ArgumentException) { }
            return Task.FromResult(true);
        }

        private static string SafeVersion(string value)
        {
            return new string((value ?? "update").Where(character => Char.IsLetterOrDigit(character) || character == '.' || character == '-' || character == '_').Take(32).ToArray());
        }

        private async Task BootstrapNodeServiceAsync(bool forceEnrollment = false)
        {
            if (serviceBridge == null || !HasActiveCredential() || clientConfiguration == null || !clientConfiguration.HasControlPlane) return;
            await nodeBootstrapGate.WaitAsync();
            try
            {
                if (!credential.NodeConsent)
                {
                    await serviceBridge.BootstrapNodeDisabledAsync(CancellationToken.None);
                    try { await controlPlane.DisableExitNodeAsync(credential.DeviceToken, CancellationToken.None); }
                    catch (ControlPlaneException) { }
                    nodeServiceState = "not-provisioned";
                }
                else if (!credential.NodeParticipationEnabled)
                {
                    await serviceBridge.DeprovisionNodeAsync(CancellationToken.None);
                    nodeServiceError = null;
                    try { await controlPlane.DisableExitNodeAsync(credential.DeviceToken, CancellationToken.None); }
                    catch (ControlPlaneException ex) { nodeServiceError = ex.ErrorCode; }
                    nodeServiceState = "participation-disabled";
                }
                else
                {
                    bool needsEnrollment = forceEnrollment;
                    if (!needsEnrollment)
                    {
                        try
                        {
                            HandShake.ServiceIntegration.ServiceStatus current = await serviceBridge.GetNodeStatusAsync(CancellationToken.None);
                            needsEnrollment = current == null || current.state == "not-provisioned" ||
                                current.state == "consent-required" || current.state == "error" || current.state == "unknown";
                            if (!needsEnrollment) nodeServiceState = current.state;
                        }
                        catch (ServiceBridgeException ex)
                        {
                            // An elevated first launch can leave no interactive
                            // owner. Recover only with the existing, consented
                            // server credential; do not loosen pipe permissions.
                            if (!String.Equals(ex.ErrorCode, "access_denied", StringComparison.Ordinal)) throw;
                            needsEnrollment = true;
                        }
                    }
                    if (needsEnrollment)
                    {
                        await serviceBridge.BootstrapNodeAsync(credential, true, CancellationToken.None);
                        nodeServiceState = "starting";
                    }
                }
                if (credential.NodeParticipationEnabled || !credential.NodeConsent) nodeServiceError = null;
            }
            catch (ControlPlaneException ex)
            {
                nodeServiceError = ex.ErrorCode;
                nodeServiceState = "control-plane-unavailable";
                ReportDiagnostic("node_sync_failed");
            }
            catch (ServiceBridgeException ex)
            {
                nodeServiceError = ex.ErrorCode;
                nodeServiceState = "unavailable";
                ReportDiagnostic(NodeServiceDiagnosticCode(ex.ErrorCode));
            }
            finally { nodeBootstrapGate.Release(); }
            ApplyServiceStatusText();
        }

        private static string NodeServiceDiagnosticCode(string errorCode)
        {
            if (String.Equals(errorCode, "service_access_denied", StringComparison.Ordinal))
                return "node_deprovision_failed";
            if (String.Equals(errorCode, "access_denied", StringComparison.Ordinal))
                return "node_disable_confirm_failed";
            if (String.Equals(errorCode, "configuration_error", StringComparison.Ordinal))
                return "node_sync_failed";
            if (String.Equals(errorCode, "local_access_denied", StringComparison.Ordinal))
                return "node_disable_confirm_failed";
            if (String.Equals(errorCode, "windows_error", StringComparison.Ordinal))
                return "node_runtime_error";
            if (String.Equals(errorCode, "service_authentication_failed", StringComparison.Ordinal))
                return "node_sync_failed";
            if (String.Equals(errorCode, "service_unavailable", StringComparison.Ordinal))
                return "node_heartbeat_failed";
            if (String.Equals(errorCode, "local_io_error", StringComparison.Ordinal))
                return "node_disable_confirm_failed";
            if (String.Equals(errorCode, "secure_storage_error", StringComparison.Ordinal))
                return "node_heartbeat_failed";
            if (String.Equals(errorCode, "local_state_error", StringComparison.Ordinal) ||
                String.Equals(errorCode, "invalid_service_response", StringComparison.Ordinal))
                return "node_sync_failed";
            if (String.Equals(errorCode, "exit_enrollment_rejected", StringComparison.Ordinal) ||
                String.Equals(errorCode, "exit_consent_required", StringComparison.Ordinal) ||
                String.Equals(errorCode, "invalid_node_profile", StringComparison.Ordinal))
                return "node_re_enrollment_failed";
            return "node_apply_failed";
        }

        private async Task SetNodeParticipationAsync(bool enabled)
        {
            if (nodeParticipationBusy || !HasActiveCredential() || !credential.NodeConsent) return;
            nodeParticipationBusy = true;
            UpdateNodeParticipationUi();
            credential.NodeParticipationEnabled = enabled;
            try { credentialStore.Save(credential); }
            catch (Exception ex)
            {
                if (!(ex is IOException) && !(ex is UnauthorizedAccessException) && !(ex is System.Security.Cryptography.CryptographicException)) throw;
                nodeServiceError = "credential_store_error";
            }
            if (enabled)
            {
                await BootstrapNodeServiceAsync(true);
            }
            else
            {
                try
                {
                    if (serviceBridge != null) await serviceBridge.DeprovisionNodeAsync(CancellationToken.None);
                    nodeServiceState = "participation-disabled";
                    nodeServiceError = null;
                }
                catch (ServiceBridgeException ex)
                {
                    nodeServiceError = ex.ErrorCode;
                    nodeServiceState = "error";
                    ReportDiagnostic("node_deprovision_failed");
                }
                try { await controlPlane.DisableExitNodeAsync(credential.DeviceToken, CancellationToken.None); }
                catch (ControlPlaneException ex)
                {
                    nodeServiceError = ex.ErrorCode;
                    ReportDiagnostic("node_disable_confirm_failed");
                }
            }
            nodeParticipationBusy = false;
            UpdateNodeParticipationUi();
            ApplyServiceStatusText();
        }

        private void UpdateNodeParticipationUi()
        {
            if (window == null) return;
            bool visible = HasActiveCredential() && credential.NodeConsent;
            StackPanel panel = Get<StackPanel>("NodeParticipationPanel");
            CheckBox toggle = Get<CheckBox>("NodeParticipationToggle");
            TextBlock status = Get<TextBlock>("NodeParticipationStatus");
            if (panel != null) panel.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
            if (toggle != null)
            {
                bool previous = loadingSettings;
                loadingSettings = true;
                toggle.IsChecked = visible && credential.NodeParticipationEnabled;
                toggle.IsEnabled = visible && !nodeParticipationBusy;
                loadingSettings = previous;
            }
            if (status != null) status.Text = nodeServiceError == null ? NodeServiceStatusText(false) :
                (english ? "Could not update Node Service" : "Не удалось обновить Node Service");
        }

        private async Task RefreshServiceStatusesAsync()
        {
            if (testing || serviceBridge == null || clientConfiguration == null || !clientConfiguration.HasControlPlane)
            {
                nodeServiceState = "unavailable";
                ApplyServiceStatusText();
                return;
            }
            try
            {
                HandShake.ServiceIntegration.ServiceStatus status = await serviceBridge.GetNodeStatusAsync(CancellationToken.None);
                nodeServiceState = status == null || String.IsNullOrWhiteSpace(status.state) ? "unknown" : status.state;
                nodeServiceError = null;
            }
            catch (ServiceBridgeException ex)
            {
                nodeServiceState = "unavailable";
                nodeServiceError = ex.ErrorCode;
            }
            ApplyServiceStatusText();
        }

        private async Task RefreshVpnHealthAsync()
        {
            if (testing || serviceBridge == null || vpnHealthBusy || vpnDisconnectBusy ||
                connection.State == ConnectionState.Connecting) return;
            vpnHealthBusy = true;
            int generation = vpnCommandGeneration;
            try {
                HandShake.ServiceIntegration.ServiceStatus status = await serviceBridge.GetVpnStatusAsync(CancellationToken.None);
                // Do not apply a status read which raced a user command.
                if (generation != vpnCommandGeneration || vpnDisconnectBusy || connection.State == ConnectionState.Connecting) return;
                vpnNeedsDisconnect = vpnNeedsDisconnect || VpnConnectionHealth.NeedsDisconnect(status);
                vpnTrafficSafety = status.trafficSafety;
                bool protectedTunnel = VpnConnectionHealth.IsProtected(status, DateTime.UtcNow);
                if (connection.State == ConnectionState.Connected && (!protectedTunnel ||
                    preparedSession == null || status.sessionId != preparedSession.sessionId)) {
                    vpnNeedsDisconnect = true;
                    connection.Fail();
                    connectionError = english
                        ? "The protected tunnel stopped. Disconnect to restore ordinary internet."
                        : "Защищённый туннель остановлен. Отключите VPN для восстановления обычного интернета.";
                } else if (connection.State == ConnectionState.Disconnected && vpnNeedsDisconnect) {
                    connection.Fail();
                    connectionError = protectedTunnel
                        ? (english ? "A VPN session is already active. You can disconnect it here."
                            : "VPN-сеанс уже активен. Здесь его можно отключить.")
                        : (english ? "Kill switch is blocking traffic. Disconnect to restore ordinary internet."
                            : "Kill switch блокирует трафик. Отключите VPN для восстановления обычного интернета.");
                }
                RenderConnection();
            } catch (ServiceBridgeException) {
                if (generation == vpnCommandGeneration && connection.State == ConnectionState.Connected) {
                    connection.Fail();
                    vpnNeedsDisconnect = true;
                    connectionError = english ? "VPN service status is unavailable. Network restoration is not confirmed."
                        : "Статус службы VPN недоступен. Восстановление сети не подтверждено.";
                    RenderConnection();
                }
            } finally { vpnHealthBusy = false; }
        }

        private string NodeServiceStatusText(bool includePrefix)
        {
            string value;
            if (nodeServiceState == "available" || nodeServiceState == "available-control-plane-degraded")
                value = english ? "sharing is active" : "раздача активна";
            else if (nodeServiceState == "starting")
                value = english ? "starting" : "запускается";
            else if (nodeServiceState == "participation-disabled")
                value = english ? "sharing is disabled" : "раздача выключена";
            else if (nodeServiceState == "consent-required")
                value = english ? "exit access is not enabled" : "выходной узел не включён";
            else if (nodeServiceState == "not-provisioned")
                value = english ? "not provisioned" : "не настроена";
            else if (nodeServiceState == "disabled-by-control-plane")
                value = english ? "disabled by server" : "отключена сервером";
            else if (nodeServiceState == "control-plane-unavailable")
                value = english ? "waiting for server" : "ожидает сервер";
            else if (nodeServiceState == "error")
                value = english ? "configuration error" : "ошибка конфигурации";
            else
                value = english ? "service unavailable" : "служба недоступна";
            return (includePrefix ? "Node Service · " : String.Empty) + value;
        }

        private void ApplyServiceStatusText()
        {
            if (window == null) return;
            TextBlock home = Get<TextBlock>("NodeServiceStatus");
            TextBlock menu = Get<TextBlock>("MenuNodeStatus");
            bool show = HasActiveCredential() && credential.NodeConsent;
            if (home != null) { home.Visibility = show ? Visibility.Visible : Visibility.Collapsed; home.Text = "○  " + NodeServiceStatusText(true); }
            if (menu != null) { menu.Visibility = show ? Visibility.Visible : Visibility.Collapsed; menu.Text = NodeServiceStatusText(true); }
            if (trayNodeItem != null) { trayNodeItem.Visible = show; trayNodeItem.Text = NodeServiceStatusText(true); }
            UpdateNodeParticipationUi();
        }

        private string ServiceError(string code)
        {
            if (code == "service_unavailable") return english ? "The Windows VPN service is unavailable." : "Служба VPN Windows недоступна.";
            if (code == "service_access_denied") return english ? "Windows denied access to the VPN service." : "Windows запретила доступ к службе VPN.";
            if (code == "access_denied") return english ? "The VPN service could not verify this Windows user's access." : "Служба VPN не смогла подтвердить доступ этого пользователя Windows.";
            if (code == "invalid_transport" || code == "invalid_session") return english ? "The server returned unsafe connection data." : "Сервер вернул небезопасные параметры подключения.";
            if (code == "firewall_error") return english ? "The kill switch could not be applied." : "Не удалось включить kill switch.";
            if (code == "native_wfp_required") return english ? "This production session requires the native WFP kill switch." : "Для рабочего подключения требуется нативный kill switch на WFP.";
            return english ? "The VPN service rejected the connection." : "Служба VPN отклонила подключение.";
        }

        private bool CanCloseActivation()
        {
            return (testing && clientConfiguration.Environment == ClientEnvironmentKind.Demo) || HasActiveCredential();
        }

        private void InitializeActivationUi()
        {
            if (testing)
            {
                Get<Grid>("ActivationOverlay").Visibility = Visibility.Collapsed;
                Get<Grid>("HomeContent").IsEnabled = true;
                return;
            }
            UpdateActivationUi();
            if (HasActiveCredential())
            {
                Get<Grid>("ActivationOverlay").Visibility = Visibility.Collapsed;
                Get<Grid>("HomeContent").IsEnabled = true;
            }
            else ShowActivation();
        }

        private void ShowActivation()
        {
            HideOverlay();
            UpdateActivationUi();
            Get<Grid>("ActivationOverlay").Visibility = Visibility.Visible;
            Get<Grid>("HomeContent").IsEnabled = false;
            if (clientConfiguration.HasControlPlane) Get<TextBox>("ActivationKey").Focus();
        }

        private void UpdateActivationUi()
        {
            bool demo = testing && clientConfiguration.Environment == ClientEnvironmentKind.Demo;
            bool test = clientConfiguration.Environment == ClientEnvironmentKind.Test;
            bool insecure = clientConfiguration.ApiBaseUri != null && clientConfiguration.ApiBaseUri.Scheme == Uri.UriSchemeHttp;
            Get<TextBlock>("ActivationModeText").Text = demo
                ? (english ? "DEMO / NO SERVER" : "ДЕМО / БЕЗ СЕРВЕРА")
                : test ? (insecure ? (english ? "TEST · HTTP WITHOUT TLS" : "ТЕСТ · HTTP БЕЗ TLS") : (english ? "TEST SERVER" : "ТЕСТОВЫЙ СЕРВЕР"))
                : (english ? "ACTIVATION" : "АКТИВАЦИЯ");
            Get<Border>("ActivationModeBadge").Background = Brush(insecure ? "#FFE5C2" : demo ? "#E4EEFF" : "#DDF5EA");
            Get<TextBlock>("ActivationTitle").Text = HasActiveCredential()
                ? (english ? "HandShake is activated" : "HandShake активирован")
                : (english ? "Activate HandShake" : "Активируйте HandShake");
            Get<TextBlock>("ActivationDescription").Text = demo
                ? (english ? "No control server is configured. You can open the clearly labelled interface preview." : "Сервер управления не настроен. Можно открыть явно обозначенный предпросмотр интерфейса.")
                : (english ? "Enter the monthly key from the website. No account is required." : "Введите месячный ключ, полученный на сайте. Регистрация не нужна.");
            Get<TextBlock>("ActivationKeyLabel").Text = english ? "Activation key" : "Ключ активации";
            Get<Button>("ActivateButton").Content = english ? "Activate" : "Активировать";
            Get<Button>("ActivateButton").Visibility = demo ? Visibility.Collapsed : Visibility.Visible;
            Get<TextBox>("ActivationKey").Visibility = demo ? Visibility.Collapsed : Visibility.Visible;
            Get<TextBlock>("ActivationKeyLabel").Visibility = demo ? Visibility.Collapsed : Visibility.Visible;
            Get<Button>("ContinueDemo").Content = english ? "Open interface preview" : "Открыть предпросмотр";
            Get<Button>("ContinueDemo").Visibility = demo ? Visibility.Visible : Visibility.Collapsed;
            Get<Button>("CloseActivation").Visibility = CanCloseActivation() ? Visibility.Visible : Visibility.Collapsed;
            Get<TextBlock>("IdentityStatus").Text = deviceIdentity != null && deviceIdentity.IsHardwareBound
                ? (english ? "Device binding uses only a SHA-256 hash of the system disk identifier; the raw serial is not saved or sent." : "Для привязки используется только SHA-256-хеш идентификатора системного диска; исходный серийный номер не сохраняется и не отправляется.")
                : (english ? "The system disk identifier is unavailable. Activation and VPN connection are blocked." : "Идентификатор системного диска недоступен. Активация и подключение VPN заблокированы.");
            Get<TextBlock>("TransportStatus").Text = english
                ? "Session data is delivered to the Windows services through a protected local channel; activation alone does not start a tunnel."
                : "Параметры сеанса передаются службам Windows через защищённый локальный канал; сама активация не включает туннель.";
            if (!String.IsNullOrWhiteSpace(configurationError))
                Get<TextBlock>("ActivationStatus").Text = english ? "Configuration error: " + configurationError : "Ошибка конфигурации: " + configurationError;
            Get<Button>("ActivateButton").IsEnabled = String.IsNullOrWhiteSpace(configurationError);
            if (String.IsNullOrWhiteSpace(configurationError) && HasActiveCredential())
                Get<TextBlock>("ActivationStatus").Text = (english ? "Valid until " : "Действует до ") + credential.ExpiresAtUtc.ToLocalTime().ToString("dd.MM.yyyy HH:mm");
            Get<Button>("NavActivation").Content = HasActiveCredential()
                ? (english ? "⌁   Activation · active" : "⌁   Активация · активна")
                : (english ? "⌁   Activation" : "⌁   Активация");
        }

        private async void Activate()
        {
            if (!String.IsNullOrWhiteSpace(configurationError) || !clientConfiguration.HasControlPlane || controlPlane == null) return;
            if (!testing && (deviceIdentity == null || !deviceIdentity.IsHardwareBound))
            {
                Get<TextBlock>("ActivationStatus").Text = english
                    ? "The system disk identifier could not be read. Activation was not attempted."
                    : "Не удалось прочитать идентификатор системного диска. Активация не выполнялась.";
                return;
            }
            string key = Get<TextBox>("ActivationKey").Text.Trim();
            if (key.Length < 8)
            {
                Get<TextBlock>("ActivationStatus").Text = english ? "Enter the complete activation key." : "Введите ключ активации полностью.";
                return;
            }
            var button = Get<Button>("ActivateButton");
            button.IsEnabled = false;
            button.Content = english ? "Activating…" : "Активация…";
            Get<TextBlock>("ActivationStatus").Foreground = Brush("#526B8D");
            Get<TextBlock>("ActivationStatus").Text = english ? "Contacting the control server…" : "Обращаемся к серверу управления…";
            try
            {
                DeviceCredential activated = await controlPlane.ActivateAsync(key, deviceIdentity, CancellationToken.None);
                credentialStore.Save(activated);
                credential = activated;
                await BootstrapNodeServiceAsync(true);
                Get<TextBox>("ActivationKey").Text = String.Empty;
                Get<TextBlock>("ActivationStatus").Foreground = Brush("#247552");
                Get<TextBlock>("ActivationStatus").Text = nodeServiceError == null
                    ? (english ? "Activated. Loading available nodes…" : "Активировано. Загружаем доступные узлы…")
                    : (english ? "Activated. The Node Service could not be initialized." : "Активировано. Не удалось инициализировать Node Service.");
                UpdateActivationUi();
                Get<Grid>("ActivationOverlay").Visibility = Visibility.Collapsed;
                Get<Grid>("HomeContent").IsEnabled = true;
                try { await RefreshCatalogFromServerCore(); }
                catch (ControlPlaneException catalogException)
                {
                    catalogError = ActivationError(catalogException.ErrorCode);
                    ReportDiagnostic("catalog_refresh_failed");
                    nodes = new List<Node>();
                    RebindCatalog();
                }
            }
            catch (ControlPlaneException ex)
            {
                Get<TextBox>("ActivationKey").Text = String.Empty;
                Get<TextBlock>("ActivationStatus").Foreground = Brush("#B33A4A");
                Get<TextBlock>("ActivationStatus").Text = ActivationError(ex.ErrorCode);
            }
            catch (IOException)
            {
                Get<TextBlock>("ActivationStatus").Foreground = Brush("#B33A4A");
                Get<TextBlock>("ActivationStatus").Text = english ? "The protected token could not be saved." : "Не удалось сохранить защищённый токен устройства.";
            }
            catch (UnauthorizedAccessException)
            {
                Get<TextBlock>("ActivationStatus").Foreground = Brush("#B33A4A");
                Get<TextBlock>("ActivationStatus").Text = english ? "Windows denied access to the protected token store." : "Windows запретила доступ к хранилищу защищённого токена.";
            }
            finally
            {
                button.IsEnabled = true;
                button.Content = english ? "Activate" : "Активировать";
            }
        }

        private string ActivationError(string code)
        {
            if (code == "not_authorized") return english ? "The key is invalid or has expired." : "Ключ недействителен или срок его действия истёк.";
            if (code == "device_mismatch") return english ? "This key is already bound to another device." : "Этот ключ уже привязан к другому устройству.";
            if (code == "rate_limited") return english ? "Too many attempts. Wait and try again." : "Слишком много попыток. Подождите и повторите.";
            if (code == "timeout") return english ? "The server did not respond in time." : "Сервер не ответил вовремя.";
            if (code == "network_error") return english ? "Could not reach the control server." : "Не удалось связаться с сервером управления.";
            return english ? "Activation failed. Please try again." : "Не удалось активировать приложение. Попробуйте снова.";
        }

        private async void RefreshCatalogFromServer()
        {
            ControlPlaneException failure = null;
            try { await RefreshCatalogFromServerCore().ConfigureAwait(false); }
            catch (ControlPlaneException ex) { failure = ex; }
            if (failure != null)
            {
                await RunOnUiAsync(delegate {
                    catalogError = ActivationError(failure.ErrorCode);
                    ReportDiagnostic("catalog_refresh_failed");
                    if (failure.ErrorCode == "not_authorized")
                    {
                        credentialStore.Clear(); credential = null; nodes = new List<Node>();
                        RebindCatalog(); ShowActivation();
                    }
                    else RefreshCatalog();
                }).ConfigureAwait(false);
            }
        }

        private async Task RefreshCatalogFromServerCore()
        {
            if (!HasActiveCredential() || controlPlane == null) return;
            IList<Node> received = await controlPlane.GetNodesAsync(
                credential.DeviceToken, CancellationToken.None).ConfigureAwait(false);
            var locationSource = controlPlane as IClientLocationSource;
            Node location = locationSource == null ? null : locationSource.SelfLocation;
            await RunOnUiAsync(delegate { selfLocation = location; }).ConfigureAwait(false);
            await ApplyCatalogOnUiAsync(received).ConfigureAwait(false);
        }

        private Task ApplyCatalogOnUiAsync(IList<Node> received)
        {
            return RunOnUiAsync(delegate {
                nodes = received ?? (IList<Node>)new List<Node>();
                catalogError = null;
                RebindCatalog();
            });
        }

        private Task RunOnUiAsync(Action action)
        {
            if (action == null) throw new ArgumentNullException("action");
            if (window == null || window.Dispatcher.CheckAccess())
            {
                action();
                return Task.FromResult(true);
            }
            return window.Dispatcher.InvokeAsync(action).Task;
        }

        private void RebindCatalog()
        {
            CancelMapSearch();
            var picker = Get<ComboBox>("LocationPicker");
            picker.ItemsSource = null;
            picker.ItemsSource = nodes;
            DrawMap();
            Node best = ConnectionController.Fastest(nodes);
            foreach (var node in nodes) node.DisplayLabel = NodeLabel(node) + " · " + LatencyLabel(node);
            picker.SelectedItem = best;
            RebindHomeLocations();
            SelectMapNode(best);
            RefreshCatalog();
        }

        private void Restore() { window.Show(); window.WindowState = WindowState.Normal; window.Activate(); }

        private void ShowPage(string page)
        {
            HideOverlay();
            if (page == "Settings") { ShowOverlay("Settings"); return; }
            if (page == "Home") { mapWindow.Hide(); Restore(); return; }
            mapWindow.Show();
            mapWindow.WindowState = WindowState.Normal;
            mapWindow.Activate();
        }

        private void ShowOverlay(string name)
        {
            menuClosing = false;
            Get<Grid>("MenuOverlay").Visibility = name == "Menu" ? Visibility.Visible : Visibility.Collapsed;
            Get<Grid>("SettingsOverlay").Visibility = name == "Settings" ? Visibility.Visible : Visibility.Collapsed;
            Get<Grid>("HomeContent").IsEnabled = false;
            var panel = Get<Grid>(name + "Overlay");
            KeyboardNavigation.SetTabNavigation(panel, KeyboardNavigationMode.Cycle);
            if (name == "Menu")
            {
                var menu = Get<Border>("MenuPanel");
                var backdrop = Get<Border>("MenuBackdrop");
                var slide = new DoubleAnimation(-300, 0, TimeSpan.FromMilliseconds(330)) {
                    EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                };
                ((TranslateTransform)menu.RenderTransform).BeginAnimation(TranslateTransform.XProperty, slide);
                menu.BeginAnimation(UIElement.OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(220)));
                backdrop.BeginAnimation(UIElement.OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(260)));
            }
            Get<Button>(name == "Menu" ? "CloseMenu" : "CloseSettings").Focus();
        }

        private void HideOverlay()
        {
            var menuOverlay = Get<Grid>("MenuOverlay");
            if (menuOverlay.Visibility == Visibility.Visible && !menuClosing && SystemParameters.ClientAreaAnimation)
            {
                menuClosing = true;
                var menu = Get<Border>("MenuPanel");
                var backdrop = Get<Border>("MenuBackdrop");
                var slide = new DoubleAnimation(0, -300, TimeSpan.FromMilliseconds(230)) {
                    EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn }
                };
                slide.Completed += delegate {
                    menuClosing = false;
                    menuOverlay.Visibility = Visibility.Collapsed;
                    menu.Opacity = 0;
                    backdrop.Opacity = 0;
                    ((TranslateTransform)menu.RenderTransform).X = -300;
                };
                ((TranslateTransform)menu.RenderTransform).BeginAnimation(TranslateTransform.XProperty, slide);
                menu.BeginAnimation(UIElement.OpacityProperty, new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(180)));
                backdrop.BeginAnimation(UIElement.OpacityProperty, new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(210)));
            }
            else if (menuOverlay.Visibility == Visibility.Visible)
                menuOverlay.Visibility = Visibility.Collapsed;
            Get<Grid>("SettingsOverlay").Visibility = Visibility.Collapsed;
            Get<Grid>("HomeContent").IsEnabled = true;
            Get<Button>("MenuButton").Focus();
        }

        private void StartWaveAnimations()
        {
            AnimateWave(Get<System.Windows.Shapes.Path>("Wave1"), -120, 20, 19, .54, .82);
            AnimateWave(Get<System.Windows.Shapes.Path>("Wave2"), -70, -190, 27, .42, .70);
            AnimateWave(Get<System.Windows.Shapes.Path>("Wave3"), -180, -15, 23, .35, .68);
            var glow = Get<Ellipse>("WaveGlow");
            glow.BeginAnimation(Canvas.LeftProperty, new DoubleAnimation(-90, 70, TimeSpan.FromSeconds(24)) {
                AutoReverse = true, RepeatBehavior = RepeatBehavior.Forever,
                EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut }
            });
            glow.BeginAnimation(UIElement.OpacityProperty, new DoubleAnimation(.35, .72, TimeSpan.FromSeconds(13)) {
                AutoReverse = true, RepeatBehavior = RepeatBehavior.Forever
            });
        }

        private static void AnimateWave(FrameworkElement wave, double from, double to, double seconds, double opacityFrom, double opacityTo)
        {
            wave.BeginAnimation(Canvas.LeftProperty, new DoubleAnimation(from, to, TimeSpan.FromSeconds(seconds)) {
                AutoReverse = true, RepeatBehavior = RepeatBehavior.Forever,
                EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut }
            });
            wave.BeginAnimation(UIElement.OpacityProperty, new DoubleAnimation(opacityFrom, opacityTo, TimeSpan.FromSeconds(seconds * .65)) {
                AutoReverse = true, RepeatBehavior = RepeatBehavior.Forever
            });
        }

        private void TogglePinned()
        {
            window.Topmost = !window.Topmost;
            Get<Button>("PinWindow").Background = window.Topmost ? Brush("#42FFFFFF") : Brushes.Transparent;
            Get<Button>("PinWindow").Opacity = window.Topmost ? 1 : .72;
            Get<Button>("PinWindow").ToolTip = window.Topmost
                ? (english ? "Unpin window" : "Открепить окно")
                : (english ? "Keep window on top" : "Закрепить поверх окон");
            AutomationPropertiesName(Get<Button>("PinWindow"), Get<Button>("PinWindow").ToolTip.ToString());
        }

        private string Country(Node node)
        {
            if (node == null) return String.Empty;
            if (!english) return node.Country;
            switch (node.Id) {
                case "nl": return "Netherlands"; case "de": return "Germany";
                case "fi": return "Finland"; case "gb": return "United Kingdom";
                case "us": return "United States"; case "jp": return "Japan";
                case "sg": return "Singapore"; default: return node.Country;
            }
        }

        private string City(Node node)
        {
            if (node == null) return String.Empty;
            if (!english) return node.City;
            switch (node.Id) {
                case "nl": return "Amsterdam"; case "de": return "Frankfurt";
                case "fi": return "Helsinki"; case "gb": return "London";
                case "us": return "New York"; case "jp": return "Tokyo";
                case "sg": return "Singapore"; default: return node.City;
            }
        }

        private string NodeLabel(Node node) { return Country(node) + " · " + City(node); }
        private string LatencyLabel(Node node) { return node == null || node.LatencyMs < 0 ? "— ms" : "~" + node.LatencyMs + " ms"; }
        private string FlagLabel(Node node)
        {
            string code = node.CountryCode;
            if (String.IsNullOrWhiteSpace(code) || code.Length != 2) return "";
            code = code.ToUpperInvariant();
            if (code.Any(c => c < 'A' || c > 'Z')) return "";
            return Char.ConvertFromUtf32(0x1F1E6 + code[0] - 'A') + Char.ConvertFromUtf32(0x1F1E6 + code[1] - 'A') + " ";
        }
        private void RebindHomeLocations()
        {
            rebindingHome = true;
            var choices = new List<Node> { new Node { Id = null, Available = true, DisplayLabel = english ? "Automatic" : "Автоматически" } };
            choices.AddRange(nodes.Where(n => n.Available).OrderBy(n => n.LatencyMs < 0 ? Int32.MaxValue : n.LatencyMs));
            var home = Get<ComboBox>("HomeLocationPicker");
            home.ItemsSource = choices;
            home.SelectedItem = choices.FirstOrDefault(n => n.Id == selectedHomeNodeId) ?? choices[0];
            selectedHomeNodeId = ((Node)home.SelectedItem).Id;
            rebindingHome = false;
        }

        private void ApplyLanguage()
        {
            bool wasLoading = loadingSettings;
            loadingSettings = true;
            foreach (var node in nodes) node.DisplayLabel = NodeLabel(node) + " · " + LatencyLabel(node);
            RebindHomeLocations();
            var picker = Get<ComboBox>("LocationPicker");
            object selected = picker.SelectedItem;
            picker.Items.Refresh();
            picker.SelectedItem = selected;

            Get<TextBlock>("PreviewLabel").Text = clientConfiguration.Environment == ClientEnvironmentKind.Demo
                ? (english ? "VPN / PREVIEW" : "VPN / ПРЕДПРОСМОТР")
                : clientConfiguration.Environment == ClientEnvironmentKind.Test
                    ? (english ? "CONTROL API / TEST" : "CONTROL API / ТЕСТ")
                    : (english ? "CONTROL API / ACTIVATED" : "CONTROL API / АКТИВАЦИЯ");
            Get<Border>("LogoPlaceholder").ToolTip = english ? "HandShake logo" : "Логотип HandShake";
            Get<TextBlock>("BestNodeLabel").Text = english ? "CONNECTION LOCATION" : "ЛОКАЦИЯ ПОДКЛЮЧЕНИЯ";
            Get<TextBlock>("SpeedUnit").Text = " ms";
            Get<TextBlock>("PreviewWarning").Text = clientConfiguration.Environment == ClientEnvironmentKind.Demo
                ? (english ? "Preview · VPN does not protect traffic" : "Предпросмотр · VPN не защищает трафик")
                : (english ? "The Windows service applies the tunnel and kill switch" : "Туннель и kill switch применяет служба Windows");
            Get<TextBlock>("MenuTitle").Text = english ? "Menu" : "Меню";
            Get<Button>("NavMap").Content = english ? "◎   Network map" : "◎   Карта сети";
            Get<Button>("NavSettings").Content = english ? "⚙   Appearance" : "⚙   Оформление";
            Get<Button>("RestoreNetwork").Content = english ? "Restore ordinary internet" : "Восстановить обычную сеть";
            Get<Button>("ActivationRestoreNetwork").Content = english ? "Restore ordinary internet" : "Восстановить обычную сеть";
            Get<Button>("LanguageButton").Content = english ? "RU   Русский" : "EN   English";
            Get<Button>("MenuHide").Content = english ? "Minimize to tray" : "Свернуть в трей";
            Get<TextBlock>("SettingsTitle").Text = english ? "Appearance" : "Оформление";
            Get<TextBlock>("SettingsIntro").Text = english ? "Appearance is saved on this device." : "Оформление сохраняется на этом устройстве.";
            Get<TextBlock>("AccentLabel").Text = english ? "Accent color" : "Основной цвет";
            Get<TextBlock>("CustomColorLabel").Text = english ? "Custom color (for example, #2864EB)" : "Свой цвет (например, #2864EB)";
            Get<Button>("ApplyAccent").Content = english ? "Apply" : "Применить";
            Get<TextBlock>("BackgroundLabel").Text = english ? "Background style" : "Оттенок фона";
            Get<TextBlock>("FontLabel").Text = english ? "Interface font" : "Шрифт интерфейса";
            Get<TextBlock>("ScenarioLabel").Text = english ? "Scenario testing" : "Проверка сценариев";
            Get<CheckBox>("SimulateError").Content = english ? "Simulate a connection error" : "Сымитировать ошибку подключения";
            Get<TextBlock>("NodeParticipationLabel").Text = english ? "Exit-node participation" : "Участие выходного узла";
            Get<CheckBox>("NodeParticipationToggle").Content = english ? "Allow other users to exit through my public IP" : "Предоставлять выход через мой публичный IP";
            Get<Button>("ResetSettings").Content = english ? "Reset appearance" : "Сбросить оформление";

            int backgroundIndex = Math.Max(0, Get<ComboBox>("BackgroundPicker").SelectedIndex);
            Get<ComboBox>("BackgroundPicker").ItemsSource = english
                ? new[] { "Dark blue waves", "Deep blue", "Solid color" }
                : new[] { "Тёмно-синие волны", "Глубокий синий", "Однотонный" };
            Get<ComboBox>("BackgroundPicker").SelectedIndex = backgroundIndex;

            Get<TextBlock>("MapTitle").Text = english ? "Network map" : "Карта сети";
            Get<TextBlock>("MapLegend").Text = clientConfiguration.Environment == ClientEnvironmentKind.Demo
                ? (english ? "● Available nodes     • Your position — orange (demo)" : "● Доступные узлы     • Ваша позиция — оранжевая (демо)")
                : (english ? "● Nodes reported by the control server" : "● Узлы, полученные от сервера управления");
            Get<Button>("ZoomReset").Content = english ? "World" : "Мир";
            Get<Button>("MapConnect").Content = Get<Button>("MapConnect").IsEnabled
                ? (english ? "Connect" : "Подключиться")
                : (english ? "Searching…" : "Подбираем…");
            Get<TextBlock>("MapSource").Text = english
                ? "Approximate cities · Natural Earth · IP Geolocation by DB-IP · db-ip.com"
                : "Города приблизительно · Natural Earth · IP Geolocation by DB-IP · db-ip.com";
            window.Title = english ? "HandShake VPN" : "HandShake VPN";
            mapWindow.Title = english ? "HandShake · Network map" : "HandShake · Карта сети";
            AutomationPropertiesName(Get<Button>("MenuButton"), english ? "Open menu" : "Открыть меню");
            AutomationPropertiesName(Get<Button>("CloseWindow"), english ? "Minimize to tray" : "Свернуть в трей");
            AutomationPropertiesName(Get<Button>("MapClose"), english ? "Close map" : "Закрыть карту");
            Get<Button>("PinWindow").ToolTip = window.Topmost
                ? (english ? "Unpin window" : "Открепить окно")
                : (english ? "Keep window on top" : "Закрепить поверх окон");
            AutomationPropertiesName(Get<Button>("PinWindow"), Get<Button>("PinWindow").ToolTip.ToString());

            foreach (var marker in Get<Canvas>("WorldMap").Children.OfType<Grid>())
                if (marker.Tag is Node) marker.ToolTip = NodeTooltip((Node)marker.Tag);
            foreach (var selfMarker in Get<Canvas>("WorldMap").Children.OfType<Ellipse>())
                if (String.Equals(selfMarker.Tag as string, "self", StringComparison.Ordinal))
                    selfMarker.ToolTip = english ? "You · Berlin (demo)" : "Вы · Берлин (пример)";
            loadingSettings = wasLoading;
            SelectMapNode(mapNode ?? ConnectionController.Fastest(nodes));
            RefreshCatalog();
            RenderConnection();
            ApplyTrayLanguage();
            UpdateActivationUi();
            ApplyServiceStatusText();
        }

        private void ApplyTrayLanguage()
        {
            if (trayOpenItem == null) return;
            trayOpenItem.Text = english ? "Open HandShake VPN" : "Открыть HandShake VPN";
            trayDisconnectItem.Text = clientConfiguration.Environment == ClientEnvironmentKind.Demo
                ? (english ? "Disconnect demo VPN" : "Отключить демо-подключение")
                : (english ? "Disconnect VPN" : "Отключить VPN");
            trayNodeItem.Text = NodeServiceStatusText(true);
            trayCloseItem.Text = english ? "Close interface" : "Закрыть интерфейс";
        }

        private void ToggleConnection()
        {
            if (vpnDisconnectBusy) return;
            if (vpnNeedsDisconnect || connection.State == ConnectionState.Connected || connection.State == ConnectionState.Connecting || connection.State == ConnectionState.SessionReady)
            {
                DisconnectPreparedSession();
                return;
            }
            if (clientConfiguration.HasControlPlane && !HasActiveCredential()) { ShowActivation(); return; }
            StartConnection(nodes.FirstOrDefault(n => n.Id == selectedHomeNodeId) ?? ConnectionController.Fastest(nodes), selectedHomeNodeId == null);
        }

        private async void DisconnectPreparedSession()
        {
            await DisconnectPreparedSessionAsync();
        }

        private async void RestoreOrdinaryNetwork()
        {
            if (vpnDisconnectBusy) return;
            HideOverlay();
            Get<TextBlock>("ActivationStatus").Text = english ? "Restoring network…" : "Восстанавливаем сеть…";
            await DisconnectPreparedSessionAsync();
            if (!vpnNeedsDisconnect) {
                Get<TextBlock>("ActivationStatus").Text = english ? "Personal VPN disconnected." : "Личный VPN отключён.";
                return;
            }
            vpnDisconnectBusy = true;
            vpnCommandGeneration++;
            try {
                string executable = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "HandShakeVpnService.exe");
                if (!File.Exists(executable)) throw new InvalidOperationException("The installed recovery component is unavailable.");
                ProcessStartInfo start = new ProcessStartInfo(executable, "--recover-network");
                start.UseShellExecute = true;
                start.Verb = "runas";
                start.WindowStyle = ProcessWindowStyle.Hidden;
                using (Process process = Process.Start(start)) {
                    bool completed = await Task.Run(delegate { return process.WaitForExit(300000); });
                    if (!completed) {
                        connectionError = english ? "Recovery is still running. Wait before connecting again."
                            : "Восстановление ещё выполняется. Подождите перед новым подключением.";
                        Get<TextBlock>("ActivationStatus").Text = connectionError;
                        RenderConnection();
                        // Never release the command gate while privileged cleanup
                        // is still mutating settings, or kill it mid-transaction.
                        await Task.Run(delegate { process.WaitForExit(); });
                    }
                    if (process.ExitCode != 0)
                        throw new InvalidOperationException("Network restoration was not confirmed.");
                }
                vpnNeedsDisconnect = false;
                vpnTrafficSafety = null;
                connection.Disconnect();
                connectionError = null;
            } catch (Exception) {
                connection.Fail();
                connectionError = english ? "Network recovery did not complete. Run HandShake Network Recovery as administrator."
                    : "Восстановление сети не завершено. Запустите HandShake Network Recovery с правами администратора.";
            } finally {
                vpnDisconnectBusy = false;
                Get<TextBlock>("ActivationStatus").Text = vpnNeedsDisconnect ? connectionError
                    : (english ? "HandShake network blocking removed." : "Блокировка сети HandShake снята.");
                RenderConnection();
            }
        }

        private async Task DisconnectPreparedSessionAsync()
        {
            if (vpnDisconnectBusy) return;
            vpnDisconnectBusy = true;
            vpnCommandGeneration++;
            if (sessionCancellation != null) sessionCancellation.Cancel();
            SessionLease lease = Interlocked.Exchange(ref preparedSession, null);
            ServiceBridgeException serviceFailure = null;
            try
            {
                if (serviceBridge == null && !testing)
                    throw new ServiceBridgeException("service_unavailable", "The VPN service connection is unavailable.");
                if (serviceBridge != null)
                    await serviceBridge.DisconnectVpnAsync(lease == null ? null : lease.sessionId, CancellationToken.None);
            }
            catch (ServiceBridgeException ex)
            {
                serviceFailure = ex;
                ReportDiagnostic("vpn_disconnect_failed");
            }
            if (lease != null && clientConfiguration != null && clientConfiguration.HasControlPlane &&
                controlPlane != null && credential != null && credential.IsUsable)
            {
                try { await controlPlane.CloseSessionAsync(credential.DeviceToken, lease.sessionId, CancellationToken.None); }
                catch (ControlPlaneException ex)
                {
                    if (serviceFailure == null) connectionError = ActivationError(ex.ErrorCode);
                    ReportDiagnostic("vpn_session_close_failed");
                }
            }
            if (serviceFailure == null)
            {
                connection.Disconnect();
                vpnNeedsDisconnect = false;
                connectionError = null;
                vpnTrafficSafety = null;
            }
            else
            {
                connection.Fail();
                vpnNeedsDisconnect = true;
                connectionError = ServiceError(serviceFailure.ErrorCode) + (english
                    ? " Traffic remains blocked until the service restores the network safely."
                    : " Трафик остаётся заблокированным, пока служба безопасно не восстановит сеть.");
            }
            vpnDisconnectBusy = false;
            RenderConnection();
        }

        private void ZoomAt(double factor, Point viewportPoint)
        {
            var scroll = Get<ScrollViewer>("MapScroll");
            var canvas = Get<Canvas>("WorldMap");
            // Preserve the geographical point under the cursor even with centered letterboxing.
            Point world = scroll.TranslatePoint(viewportPoint, canvas);
            SetMapZoom(mapZoom * factor);
            scroll.UpdateLayout();
            Point moved = canvas.TranslatePoint(world, scroll);
            scroll.ScrollToHorizontalOffset(scroll.HorizontalOffset + moved.X - viewportPoint.X);
            scroll.ScrollToVerticalOffset(scroll.VerticalOffset + moved.Y - viewportPoint.Y);
        }

        private void SetMapZoom(double value)
        {
            mapZoom = Math.Max(1, Math.Min(6, value));
            var scroll = Get<ScrollViewer>("MapScroll");
            double width = scroll.ActualWidth > 0 ? scroll.ActualWidth - 18 : 920;
            double height = scroll.ActualHeight > 0 ? scroll.ActualHeight - 18 : 440;
            Get<Viewbox>("MapView").Width = Math.Max(100, Math.Min(width, height * 1200 / 540)) * mapZoom;
        }

        private async void BeginMapConnection()
        {
            Node target = mapNode ?? ConnectionController.Fastest(nodes);
            if (target == null) return;
            int generation = ++mapSearchGeneration;
            var button = Get<Button>("MapConnect");
            button.IsEnabled = false;
            button.Content = english ? "Searching…" : "Подбираем…";
            if (!mapNodePoints.ContainsKey(target.Id))
            {
                button.IsEnabled = true;
                button.Content = english ? "Connect" : "Подключиться";
                StartConnection(target);
                await Task.Delay(220);
                ShowPage("Home");
                return;
            }
            var sequence = nodes.Where(n => n.Available && n.HasCoordinates && n.Id != target.Id)
                .OrderBy(n => n.LatencyMs).ToList();
            sequence.Add(target);
            for (int i = 0; i < sequence.Count; i++)
            {
                if (generation != mapSearchGeneration) return;
                Ellipse dot = mapSearchDots[i % mapSearchDots.Count];
                Point point = mapNodePoints[sequence[i].Id];
                dot.Visibility = Visibility.Visible;
                Canvas.SetLeft(dot, point.X - dot.Width / 2);
                Canvas.SetTop(dot, point.Y - dot.Height / 2);
                dot.BeginAnimation(UIElement.OpacityProperty, new DoubleAnimation(.25, 1, TimeSpan.FromMilliseconds(120)));
                await Task.Delay(155);
            }
            if (generation != mapSearchGeneration) return;
            foreach (Ellipse dot in mapSearchDots) dot.Visibility = Visibility.Hidden;
            Ellipse selected = mapSearchDots[0];
            Point finish = mapNodePoints[target.Id];
            Canvas.SetLeft(selected, finish.X - selected.Width / 2);
            Canvas.SetTop(selected, finish.Y - selected.Height / 2);
            selected.Visibility = Visibility.Visible;
            selected.BeginAnimation(UIElement.OpacityProperty, new DoubleAnimationUsingKeyFrames {
                KeyFrames = {
                    new DiscreteDoubleKeyFrame(1, KeyTime.FromTimeSpan(TimeSpan.Zero)),
                    new EasingDoubleKeyFrame(.35, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(180))),
                    new EasingDoubleKeyFrame(1, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(360)))
                }
            });
            await Task.Delay(430);
            if (generation != mapSearchGeneration) return;
            button.IsEnabled = true;
            button.Content = english ? "Connect" : "Подключиться";
            StartConnection(target);
            await Task.Delay(220);
            if (generation == mapSearchGeneration)
            {
                selected.Visibility = Visibility.Hidden;
                ShowPage("Home");
            }
        }

        private void CancelMapSearch()
        {
            mapSearchGeneration++;
            foreach (Ellipse dot in mapSearchDots) dot.Visibility = Visibility.Hidden;
            var button = Get<Button>("MapConnect");
            button.IsEnabled = true;
            button.Content = english ? "Connect" : "Подключиться";
        }

        private async void StartConnection(Node node, bool automatic = false)
        {
            if (vpnDisconnectBusy) return;
            vpnCommandGeneration++;
            if (!(testing && clientConfiguration.Environment == ClientEnvironmentKind.Demo) &&
                (!String.IsNullOrWhiteSpace(configurationError) || !clientConfiguration.HasControlPlane || !HasActiveCredential()))
            {
                ShowActivation(); return;
            }
            int ticket = connection.Begin(node);
            bool fail = Get<CheckBox>("SimulateError").IsChecked == true;
            Get<CheckBox>("SimulateError").IsChecked = false;
            connectionError = null;
            RenderConnection();
            if (node == null)
            {
                connectionError = english ? "No available nodes were returned." : "Сервер не вернул доступных узлов.";
                RenderConnection();
                return;
            }
            if (testing && clientConfiguration.Environment == ClientEnvironmentKind.Demo)
            {
                await Task.Delay(2500);
                if (connection.Complete(ticket, !fail)) RenderConnection();
                return;
            }
            if (fail)
            {
                await Task.Delay(600);
                connectionError = english ? "Test session error." : "Тестовая ошибка подготовки сеанса.";
                if (connection.Complete(ticket, false)) RenderConnection();
                return;
            }
            if (sessionCancellation != null) sessionCancellation.Cancel();
            var attemptCancellation = new CancellationTokenSource();
            sessionCancellation = attemptCancellation;
            SessionLease issuedLease = null;
            ControlPlaneException controlFailure = null;
            ServiceBridgeException serviceFailure = null;
            bool cancelled = false;
            try
            {
                if (serviceBridge == null)
                    throw new ServiceBridgeException("service_unavailable", "The Windows VPN service is unavailable.");
                // Finish validated ownership recovery before the VPN preflight.
                // This also serializes it with the asynchronous startup task.
                await BootstrapNodeServiceAsync();
                attemptCancellation.Token.ThrowIfCancellationRequested();
                // Check the local service before allocating a server-side route.
                // A stopped/missing service must never produce a VPN session or success UI.
                await serviceBridge.GetVpnStatusAsync(attemptCancellation.Token);
                issuedLease = await controlPlane.CreateSessionAsync(credential.DeviceToken, automatic ? null : node.Id, attemptCancellation.Token);
                VpnProfileFactory.Validate(issuedLease);
                if (issuedLease.hops != null && issuedLease.hops.Count > 0)
                    connection.SetSelected(nodes.FirstOrDefault(n => n.Id == issuedLease.hops[issuedLease.hops.Count - 1].nodeId));
                preparedSession = issuedLease;
                if (serviceBridge == null)
                    throw new ServiceBridgeException("service_unavailable", "The Windows VPN service is unavailable.");
                await serviceBridge.ProvisionVpnAsync(issuedLease, attemptCancellation.Token);
                attemptCancellation.Token.ThrowIfCancellationRequested();
                HandShake.ServiceIntegration.ServiceStatus connectedStatus =
                    await WaitForVpnConnectedAsync(issuedLease.sessionId, attemptCancellation.Token);
                vpnTrafficSafety = connectedStatus.trafficSafety;
                vpnNeedsDisconnect = true;
                attemptCancellation.Token.ThrowIfCancellationRequested();
                if (connection.Complete(ticket, true)) RenderConnection();
            }
            catch (ControlPlaneException ex)
            {
                controlFailure = ex;
            }
            catch (ServiceBridgeException ex)
            {
                serviceFailure = ex;
            }
            catch (OperationCanceledException)
            {
                cancelled = true;
            }
            if (controlFailure != null || serviceFailure != null || cancelled)
            {
                await ReleaseFailedLeaseAsync(issuedLease);
                if (cancelled || attemptCancellation.IsCancellationRequested) return;
                if (controlFailure != null)
                {
                    connectionError = ActivationError(controlFailure.ErrorCode);
                    ReportDiagnostic("vpn_session_create_failed");
                    if (connection.Complete(ticket, false)) RenderConnection();
                    if (controlFailure.ErrorCode == "not_authorized")
                    {
                        credentialStore.Clear(); credential = null; ShowActivation();
                    }
                }
                else
                {
                    connectionError = serviceFailure.ErrorCode == "service_start_failed" && !String.IsNullOrWhiteSpace(serviceFailure.Message)
                        ? serviceFailure.Message : ServiceError(serviceFailure.ErrorCode);
                    ReportDiagnostic(serviceFailure.ErrorCode == "firewall_error"
                        ? "vpn_kill_switch_failed" : "vpn_connect_failed");
                    if (connection.Complete(ticket, false)) RenderConnection();
                }
            }
        }

        private async Task<HandShake.ServiceIntegration.ServiceStatus> WaitForVpnConnectedAsync(string sessionId, CancellationToken cancellationToken)
        {
            DateTime deadline = DateTime.UtcNow.AddSeconds(HandShake.ServiceIntegration.ServiceProtocol.VpnTunnelStartupSeconds + 15);
            while (DateTime.UtcNow < deadline)
            {
                cancellationToken.ThrowIfCancellationRequested();
                HandShake.ServiceIntegration.ServiceStatus status = null;
                bool retryLocalStatus = false;
                try
                {
                    status = await serviceBridge.GetVpnStatusAsync(cancellationToken);
                }
                catch (ServiceBridgeException ex)
                {
                    // The service switches the TUN adapter and its firewall binding
                    // during this window. A single local pipe reconnect can fail while
                    // that transition completes; keep polling until the overall
                    // connection deadline instead of tearing down a healthy tunnel.
                    if (!String.Equals(ex.ErrorCode, "service_unavailable", StringComparison.Ordinal) &&
                        !String.Equals(ex.ErrorCode, "local_io_error", StringComparison.Ordinal)) throw;
                    retryLocalStatus = true;
                }
                if (retryLocalStatus) { await Task.Delay(500, cancellationToken); continue; }
                if (status != null && String.Equals(status.sessionId, sessionId, StringComparison.Ordinal) &&
                    VpnConnectionHealth.IsProtected(status, DateTime.UtcNow)) return status;
                if (status != null && String.Equals(status.state, "error", StringComparison.Ordinal))
                    throw new ServiceBridgeException("service_start_failed", String.IsNullOrWhiteSpace(status.detail)
                        ? "The Windows VPN service could not start the protected tunnel." : status.detail);
                await Task.Delay(500, cancellationToken);
            }
            throw new ServiceBridgeException("service_start_timeout", "The Windows VPN service did not confirm the protected tunnel.");
        }

        private async Task ReleaseFailedLeaseAsync(SessionLease lease)
        {
            if (lease == null) return;
            if (!Object.ReferenceEquals(Interlocked.CompareExchange(ref preparedSession, null, lease), lease)) return;
            try { if (serviceBridge != null) await serviceBridge.DisconnectVpnAsync(lease.sessionId, CancellationToken.None); }
            catch (ServiceBridgeException) { vpnNeedsDisconnect = true; }
            try
            {
                if (controlPlane != null && credential != null && credential.IsUsable)
                    await controlPlane.CloseSessionAsync(credential.DeviceToken, lease.sessionId, CancellationToken.None);
            }
            catch (ControlPlaneException) { }
        }

        private void RenderConnection()
        {
            var state = connection.State;
            bool changed = state != renderedState;
            renderedState = state;
            var face = Get<TextBlock>("Face");
            var title = Get<TextBlock>("StateTitle");
            var desc = Get<TextBlock>("StateDescription");
            var button = Get<Button>("ConnectButton");
            face.Foreground = Brush(state == ConnectionState.Connected ? "#00A8F5" : state == ConnectionState.SessionReady ? "#E6A23C" : state == ConnectionState.Error ? "#E65060" : "#8294AE");
            if (state == ConnectionState.Disconnected)
            {
                face.Text = "(=^･ω･^=)"; title.Text = english ? "Ready to connect?" : "Готовы подключиться?";
                desc.Text = english ? "We'll choose the fastest available node" : "Выберем самый быстрый доступный узел";
                button.Content = english ? "Connect" : "Подключиться";
            }
            else if (state == ConnectionState.Connecting)
            {
                face.Text = "|"; title.Text = clientConfiguration.Environment == ClientEnvironmentKind.Demo
                    ? (english ? "Connecting…" : "Устанавливаем связь…")
                    : (english ? "Preparing a session…" : "Подготавливаем сеанс…");
                desc.Text = clientConfiguration.Environment == ClientEnvironmentKind.Demo
                    ? (english ? "Demo connection to the selected node" : "Демонстрация подключения к выбранному узлу")
                    : (english ? "Applying the tunnel and kill switch through the Windows service" : "Служба Windows включает туннель и kill switch");
                button.Content = english ? "Cancel" : "Отменить";
            }
            else if (state == ConnectionState.SessionReady)
            {
                face.Text = "✓"; title.Text = english ? "Session prepared" : "Сеанс подготовлен";
                desc.Text = english ? "Waiting for the Windows service to confirm the protected tunnel" : "Ожидаем подтверждение защищённого туннеля от службы Windows";
                button.Content = english ? "Close session" : "Закрыть сеанс";
            }
            else if (state == ConnectionState.Connected)
            {
                face.Text = "･ﾟ･(｡>ω<｡)･ﾟ･\"";
                bool experimental = String.Equals(vpnTrafficSafety, "test-tun-route-no-native-killswitch", StringComparison.Ordinal);
                title.Text = clientConfiguration.Environment == ClientEnvironmentKind.Demo
                    ? (english ? "Connected · demo" : "Подключено · демо")
                    : experimental
                        ? (english ? "Connected · closed test" : "Подключено · закрытый тест")
                        : (english ? "VPN connected" : "VPN подключён");
                desc.Text = clientConfiguration.Environment == ClientEnvironmentKind.Demo
                    ? (english ? "Preview only: the real VPN is not connected" : "Это пример: реальный VPN ещё не подключён")
                    : experimental
                        ? (english ? "Closed test through the selected node; native kill switch is still in development" : "Закрытый тест через выбранный узел; системный kill switch ещё разрабатывается")
                        : (english ? "The Windows service confirmed the TUN interface and kill switch" : "Служба Windows подтвердила TUN-интерфейс и kill switch");
                button.Content = english ? "Disconnect" : "Отключиться";
            }
            else
            {
                face.Text = ":/"; title.Text = english ? "Connection failed" : "Не удалось подключиться";
                desc.Text = connectionError ?? (clientConfiguration.Environment == ClientEnvironmentKind.Demo
                    ? (english ? "Demo error. Please try again" : "Тестовая ошибка. Попробуйте снова")
                    : (english ? "The session could not be prepared" : "Не удалось подготовить сеанс"));
                button.Content = vpnNeedsDisconnect ? (english ? "Disconnect / restore internet" : "Отключить / восстановить интернет")
                    : (english ? "Try again" : "Повторить");
            }
            face.FontSize = state == ConnectionState.Connected ? 17 : 22;
            Get<TextBlock>("SessionInfo").Text = connection.Selected == null
                ? (english ? "Automatic selection · any city" : "Автоматический выбор · любой город")
                : NodeLabel(connection.Selected);
            RefreshMapConnectionDetails();
            AutomationPropertiesName(Get<Button>("CircleConnect"), button.Content.ToString());
            if (changed) AnimateConnectionState(state);
            if (tray != null) tray.Text = state == ConnectionState.Connected
                ? (clientConfiguration.Environment == ClientEnvironmentKind.Demo
                    ? (english ? "HandShake · demo connected" : "HandShake · демо-подключение")
                    : (english ? "HandShake VPN · connected" : "HandShake VPN · подключён"))
                : state == ConnectionState.SessionReady
                    ? (english ? "HandShake · session only" : "HandShake · только сеанс")
                    : clientConfiguration.Environment == ClientEnvironmentKind.Demo
                        ? (english ? "HandShake VPN · demo" : "HandShake VPN · демо")
                        : (english ? "HandShake VPN · disconnected" : "HandShake VPN · отключён");
        }


        private static void AutomationPropertiesName(DependencyObject target, string name)
        {
            System.Windows.Automation.AutomationProperties.SetName(target, name);
        }

        private void AnimateConnectionState(ConnectionState state)
        {
            var transform = (TranslateTransform)Get<TextBlock>("Face").RenderTransform;
            transform.BeginAnimation(TranslateTransform.YProperty, null);
            transform.Y = 0;
            var successFill = Get<Ellipse>("SuccessFill");
            successFill.BeginAnimation(UIElement.OpacityProperty, null);
            successFill.Opacity = 0;
            var ring = Get<Ellipse>("ConnectionRing");
            var rotation = (RotateTransform)ring.RenderTransform;
            rotation.BeginAnimation(RotateTransform.AngleProperty, null);
            rotation.Angle = 0;
            ring.Visibility = state == ConnectionState.Connecting ? Visibility.Visible : Visibility.Collapsed;
            if (state == ConnectionState.Connecting)
            {
                rotation.BeginAnimation(RotateTransform.AngleProperty, new DoubleAnimation(0, 360,
                    TimeSpan.FromSeconds(1.3)) { RepeatBehavior = RepeatBehavior.Forever });
            }
            if (state == ConnectionState.Connected && SystemParameters.ClientAreaAnimation)
            {
                // Hold the happy face for a second, then two complete hops. No delayed task
                // remains after disconnect: the animation is removed above on each transition.
                var hops = new DoubleAnimationUsingKeyFrames { Duration = TimeSpan.FromSeconds(2.1), FillBehavior = FillBehavior.Stop };
                hops.KeyFrames.Add(new DiscreteDoubleKeyFrame(0, KeyTime.FromTimeSpan(TimeSpan.Zero)));
                hops.KeyFrames.Add(new DiscreteDoubleKeyFrame(0, KeyTime.FromTimeSpan(TimeSpan.FromSeconds(1))));
                hops.KeyFrames.Add(new EasingDoubleKeyFrame(-14, KeyTime.FromTimeSpan(TimeSpan.FromSeconds(1.2)), new QuadraticEase { EasingMode = EasingMode.EaseOut }));
                hops.KeyFrames.Add(new EasingDoubleKeyFrame(0, KeyTime.FromTimeSpan(TimeSpan.FromSeconds(1.42)), new QuadraticEase { EasingMode = EasingMode.EaseIn }));
                hops.KeyFrames.Add(new DiscreteDoubleKeyFrame(0, KeyTime.FromTimeSpan(TimeSpan.FromSeconds(1.55))));
                hops.KeyFrames.Add(new EasingDoubleKeyFrame(-10, KeyTime.FromTimeSpan(TimeSpan.FromSeconds(1.75)), new QuadraticEase { EasingMode = EasingMode.EaseOut }));
                hops.KeyFrames.Add(new EasingDoubleKeyFrame(0, KeyTime.FromTimeSpan(TimeSpan.FromSeconds(1.97)), new QuadraticEase { EasingMode = EasingMode.EaseIn }));
                transform.BeginAnimation(TranslateTransform.YProperty, hops);
                var green = new DoubleAnimationUsingKeyFrames { Duration = TimeSpan.FromSeconds(2.1), FillBehavior = FillBehavior.Stop };
                green.KeyFrames.Add(new DiscreteDoubleKeyFrame(0, KeyTime.FromTimeSpan(TimeSpan.Zero)));
                green.KeyFrames.Add(new DiscreteDoubleKeyFrame(0, KeyTime.FromTimeSpan(TimeSpan.FromSeconds(1))));
                green.KeyFrames.Add(new DiscreteDoubleKeyFrame(1, KeyTime.FromTimeSpan(TimeSpan.FromSeconds(1.03))));
                green.KeyFrames.Add(new DiscreteDoubleKeyFrame(0, KeyTime.FromTimeSpan(TimeSpan.FromSeconds(1.42))));
                green.KeyFrames.Add(new DiscreteDoubleKeyFrame(1, KeyTime.FromTimeSpan(TimeSpan.FromSeconds(1.58))));
                green.KeyFrames.Add(new DiscreteDoubleKeyFrame(0, KeyTime.FromTimeSpan(TimeSpan.FromSeconds(1.97))));
                successFill.BeginAnimation(UIElement.OpacityProperty, green);
            }
        }

        private ToolTip NodeTooltip(Node node)
        {
            var lines = new StackPanel { MinWidth = 145 };
            lines.Children.Add(new TextBlock { Text = Country(node), FontWeight = FontWeights.SemiBold, FontSize = 12, Foreground = Brushes.White });
            lines.Children.Add(new TextBlock { Text = City(node), FontSize = 10, Foreground = Brush("#BDD3ED"), Margin = new Thickness(0, 2, 0, 6) });
            string exitIp = ConnectedExitIp(node);
            if (!String.IsNullOrWhiteSpace(exitIp))
                lines.Children.Add(new TextBlock { Text = "IP  " + exitIp, FontFamily = new FontFamily("Consolas"), FontSize = 10, Foreground = Brushes.White });
            lines.Children.Add(new TextBlock { Text = (english ? "Latency  " : "Задержка  ") + LatencyLabel(node), Margin = new Thickness(0, 4, 0, 0), FontSize = 10, Foreground = Brush("#70E9BB") });
            lines.Children.Add(new TextBlock { Text = clientConfiguration.Environment == ClientEnvironmentKind.Demo
                ? (english ? "Demo node" : "Демо-узел")
                : (english ? "Control-plane catalog" : "Каталог сервера управления"), FontSize = 9, Foreground = Brush("#8A9CB5"), Margin = new Thickness(0, 6, 0, 0) });
            var tip = new ToolTip { Content = lines, Background = Brush("#13213A"), Foreground = Brushes.White,
                BorderBrush = Brush("#365275"), BorderThickness = new Thickness(1), Padding = new Thickness(9),
                Placement = System.Windows.Controls.Primitives.PlacementMode.MousePoint,
                HorizontalOffset = 14, VerticalOffset = 12, HasDropShadow = true };
            return tip;
        }

        private void RefreshCatalog()
        {
            var best = nodes.FirstOrDefault(n => n.Id == selectedHomeNodeId) ?? ConnectionController.Fastest(nodes);
            if (best == null)
            {
                Get<TextBlock>("BestLocation").Text = catalogError ?? (clientConfiguration.HasControlPlane
                    ? (english ? "No available nodes" : "Нет доступных узлов")
                    : (english ? "Demo catalog is empty" : "Демонстрационный каталог пуст"));
                Get<TextBlock>("BestSpeed").Text = "—";
                Get<TextBlock>("BestMeta").Text = HasActiveCredential()
                    ? (english ? "Catalog updated " : "Каталог обновлён ") + DateTime.Now.ToString("HH:mm")
                    : (english ? "Activation required" : "Требуется активация");
                return;
            }
            Get<TextBlock>("BestLocation").Text = NodeLabel(best);
            Get<TextBlock>("BestSpeed").Text = best.LatencyMs < 0 ? "—" : "~" + best.LatencyMs;
            Get<TextBlock>("BestMeta").Text = english
                ? "Estimated latency · updated " + DateTime.Now.ToString("HH:mm")
                : "Оценочная задержка · обновлено " + DateTime.Now.ToString("HH:mm");
        }
        private string Details(Node node)
        {
            if (node == null) return english ? "No node selected" : "Узел не выбран";
            string suffix = clientConfiguration.Environment == ClientEnvironmentKind.Demo ? (english ? " (demo)" : " (демо)") : String.Empty;
            string exitIp = ConnectedExitIp(node);
            return (String.IsNullOrWhiteSpace(exitIp) ? String.Empty : "IP " + exitIp + " · ") + LatencyLabel(node) + suffix;
        }
        private string ConnectedExitIp(Node node)
        {
            if (node == null || connection.State != ConnectionState.Connected || connection.Selected == null ||
                !String.Equals(node.Id, connection.Selected.Id, StringComparison.Ordinal) || preparedSession == null ||
                preparedSession.hops == null || preparedSession.hops.Count == 0) return null;
            SessionHop exit = preparedSession.hops[preparedSession.hops.Count - 1];
            return String.Equals(exit.nodeId, node.Id, StringComparison.Ordinal) ? exit.ip : null;
        }
        private void RefreshMapConnectionDetails()
        {
            foreach (FrameworkElement marker in Get<Canvas>("WorldMap").Children.OfType<FrameworkElement>())
                if (marker.Tag is Node) marker.ToolTip = NodeTooltip((Node)marker.Tag);
            Get<TextBlock>("MapDetails").Text = Details(mapNode);
        }
        private void SelectMapNode(Node node)
        {
            mapNode = node;
            Get<TextBlock>("MapLocation").Text = node == null ? (english ? "No available nodes" : "Нет доступных узлов") : NodeLabel(node);
            Get<TextBlock>("MapDetails").Text = Details(node);
            Get<Button>("MapConnect").IsEnabled = node != null;
        }
        private static Point Project(double longitude, double latitude)
        {
            return new Point((longitude + 180) / 360 * 1200, (85 - latitude) / 145 * 540);
        }

        private void DrawMap()
        {
            var canvas = Get<Canvas>("WorldMap");
            canvas.Children.Clear();
            mapSearchDots.Clear();
            mapNodePoints.Clear();
            // A small blue pixel grid reproduces the reference's ocean texture.
            var texture = new DrawingGroup();
            using (var dc = texture.Open())
            {
                dc.DrawRectangle(Brush("#030509"), null, new Rect(0, 0, 4, 4));
                dc.DrawRectangle(Brush("#243B66"), null, new Rect(0, 0, 1.3, 1.3));
                dc.DrawRectangle(Brush("#122342"), null, new Rect(2, 2, 1, 1));
            }
            var ocean = new DrawingBrush(texture) {
                TileMode = TileMode.Tile, ViewportUnits = BrushMappingMode.Absolute,
                Viewport = new Rect(0, 0, 4, 4), Stretch = Stretch.None
            };
            ocean.Freeze();
            canvas.Background = ocean;
            string json;
            using (var reader = new StreamReader(typeof(DesktopApp).Assembly.GetManifestResourceStream("countries.geojson")))
                json = reader.ReadToEnd();
            var serializer = new System.Web.Script.Serialization.JavaScriptSerializer { MaxJsonLength = 4000000 };
            var data = (Dictionary<string, object>)serializer.DeserializeObject(json);
            foreach (Dictionary<string, object> feature in (object[])data["features"])
            {
                var properties = (Dictionary<string, object>)feature["properties"];
                if ((string)properties["ADMIN"] == "Antarctica") continue;
                var geometry = (Dictionary<string, object>)feature["geometry"];
                var coordinates = (object[])geometry["coordinates"];
                var polygons = (string)geometry["type"] == "Polygon" ? new object[] { coordinates } : coordinates;
                var shape = new StreamGeometry { FillRule = FillRule.EvenOdd };
                using (var context = shape.Open())
                {
                    foreach (object[] polygon in polygons)
                        foreach (object[] ring in polygon)
                        {
                            bool first = true;
                            foreach (object[] coord in ring)
                            {
                                Point p = Project(Convert.ToDouble(coord[0]), Convert.ToDouble(coord[1]));
                                // Subpixel snapping keeps a subtle digital edge without losing country borders.
                                p = new Point(Math.Round(p.X * 2) / 2, Math.Round(p.Y * 2) / 2);
                                if (first) { context.BeginFigure(p, true, true); first = false; }
                                else context.LineTo(p, true, false);
                            }
                        }
                }
                shape.Freeze();
                canvas.Children.Add(new System.Windows.Shapes.Path {
                    Data = shape, Fill = Brush("#03060C"), Stroke = Brush("#EAF1FF"),
                    StrokeThickness = 0.65, SnapsToDevicePixels = true, IsHitTestVisible = false
                });
            }
            foreach (Node node in nodes)
            {
                if (!node.HasCoordinates) continue;
                Node selected = node;
                var point = Project(node.Longitude, node.Latitude);
                mapNodePoints[node.Id] = point;
                var hit = new Grid { Width = 16, Height = 16, Background = Brushes.Transparent, Tag = node,
                    Cursor = System.Windows.Input.Cursors.Hand, ToolTip = NodeTooltip(node) };
                ToolTipService.SetInitialShowDelay(hit, 120);
                ToolTipService.SetBetweenShowDelay(hit, 0);
                ToolTipService.SetShowDuration(hit, 30000);
                hit.Children.Add(new Ellipse { Width = 7, Height = 7, Fill = Brush("#54E6AC"),
                    Stroke = Brush("#C6FFE8"), StrokeThickness = 1 });
                Canvas.SetLeft(hit, point.X - 8); Canvas.SetTop(hit, point.Y - 8);
                hit.MouseLeftButtonDown += delegate { Get<ComboBox>("LocationPicker").SelectedItem = selected; };
                canvas.Children.Add(hit);
            }
            for (int i = 0; i < 3; i++)
            {
                var searchDot = new Ellipse { Width = 12 - i * 2, Height = 12 - i * 2,
                    Fill = Brush(i == 0 ? "#168CFF" : "#59B7FF"), Stroke = Brushes.White,
                    StrokeThickness = 1, Visibility = Visibility.Hidden, IsHitTestVisible = false };
                Panel.SetZIndex(searchDot, 20 + i);
                mapSearchDots.Add(searchDot);
                canvas.Children.Add(searchDot);
            }
            if (selfLocation != null && selfLocation.HasCoordinates)
            {
                Point origin = Project(selfLocation.Longitude, selfLocation.Latitude);
                var me = new Ellipse { Width = 9, Height = 9, Fill = Brush("#FFAA4A"), Stroke = Brushes.White,
                    StrokeThickness = 1, Tag = "self", ToolTip = (english ? "You · " : "Вы · ") + Country(selfLocation) };
                Canvas.SetLeft(me, origin.X - 4.5); Canvas.SetTop(me, origin.Y - 4.5); canvas.Children.Add(me);
            }
            else if (clientConfiguration.Environment == ClientEnvironmentKind.Demo)
            {
                Point origin = Project(13.40, 52.52);
                var me = new Ellipse { Width = 7, Height = 7, Fill = Brush("#FFAA4A"), Stroke = Brushes.White,
                    StrokeThickness = 1, Tag = "self", ToolTip = english ? "You · Berlin (demo)" : "Вы · Берлин (пример)" };
                Canvas.SetLeft(me, origin.X - 3.5); Canvas.SetTop(me, origin.Y - 3.5); canvas.Children.Add(me);
            }
        }

        private static SolidColorBrush Brush(string hex) { return new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex)); }

        private void SetupSettings()
        {
            loadingSettings = true;
            foreach (string color in new[] { "#2889DB", "#087AA1", "#6857D9", "#187859", "#B74D65" })
            {
                string chosen = color;
                var button = new Button { Width = 48, Height = 38, Background = Brush(color), Margin = new Thickness(0, 0, 10, 0), ToolTip = color };
                button.Click += delegate { SetAccent(chosen); SaveSettings(); };
                Get<WrapPanel>("AccentOptions").Children.Add(button);
            }
            var background = Get<ComboBox>("BackgroundPicker");
            background.ItemsSource = new[] { "Тёмно-синие волны", "Глубокий синий", "Однотонный" };
            background.SelectedIndex = 0;
            background.SelectionChanged += delegate { ApplyBackground(); SaveSettings(); };
            var fonts = Get<ComboBox>("FontPicker");
            fonts.ItemsSource = new[] { "Segoe UI", "Arial", "Calibri", "Verdana", "Consolas" };
            fonts.SelectedIndex = 0;
            fonts.SelectionChanged += delegate { window.FontFamily = new FontFamily((string)fonts.SelectedItem); mapWindow.FontFamily = window.FontFamily; SaveSettings(); };
            Click("ApplyAccent", delegate {
                string value = Get<TextBox>("CustomAccent").Text.Trim();
                if (!System.Text.RegularExpressions.Regex.IsMatch(value, "^#[0-9a-fA-F]{6}$"))
                { Get<TextBlock>("SettingsStatus").Text = "Введите цвет в формате #RRGGBB."; return; }
                SetAccent(value); SaveSettings();
            });
            Click("ResetSettings", delegate { SetAccent("#2889DB"); background.SelectedIndex = 0; fonts.SelectedIndex = 0; SaveSettings(); });
            try
            {
                if (!testing && File.Exists(settingsPath))
                {
                    string[] lines = File.ReadAllLines(settingsPath);
                    if (lines.Length >= 3)
                    {
                        if (System.Text.RegularExpressions.Regex.IsMatch(lines[0], "^#[0-9a-fA-F]{6}$")) SetAccent(lines[0]);
                        int index; if (Int32.TryParse(lines[1], out index) && index >= 0 && index < 3) background.SelectedIndex = index;
                        if (fonts.Items.Contains(lines[2])) fonts.SelectedItem = lines[2];
                        if (lines.Length >= 4) english = String.Equals(lines[3], "en", StringComparison.OrdinalIgnoreCase);
                    }
                }
            }
            catch (IOException) { Get<TextBlock>("SettingsStatus").Text = "Не удалось загрузить оформление."; }
            catch (UnauthorizedAccessException) { Get<TextBlock>("SettingsStatus").Text = "Нет доступа к сохранённому оформлению."; }
            loadingSettings = false;
            SetAccent(accent);
        }
        private void SetAccent(string value)
        {
            accent = value;
            window.Resources["Accent"] = Brush(value);
            Get<TextBox>("CustomAccent").Text = value;
            ApplyBackground();
        }
        private void ApplyBackground()
        {
            Color color = (Color)ColorConverter.ConvertFromString(accent);
            int mode = Math.Max(0, Get<ComboBox>("BackgroundPicker").SelectedIndex);
            Color top = mode == 2 ? color : mode == 1
                ? Color.FromRgb((byte)(color.R * .36), (byte)(color.G * .43), (byte)(color.B * .60))
                : Color.FromRgb((byte)(color.R * .70), (byte)(color.G * .72), (byte)(color.B * .76));
            Color bottom = mode == 2 ? top : mode == 1
                ? Color.FromRgb((byte)(color.R * .18), (byte)(color.G * .23), (byte)(color.B * .38))
                : Color.FromRgb((byte)(color.R * .36), (byte)(color.G * .40), (byte)(color.B * .53));
            Get<Border>("MainSurface").Background = new LinearGradientBrush(top, bottom, 90);
        }
        private void SaveSettings()
        {
            if (loadingSettings || testing) return;
            try
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(settingsPath));
                File.WriteAllLines(settingsPath, new[] { accent, Get<ComboBox>("BackgroundPicker").SelectedIndex.ToString(), (string)Get<ComboBox>("FontPicker").SelectedItem, english ? "en" : "ru" });
                Get<TextBlock>("SettingsStatus").Text = english ? "Appearance saved." : "Оформление сохранено.";
            }
            catch (IOException) { Get<TextBlock>("SettingsStatus").Text = english ? "Could not save appearance." : "Не удалось сохранить оформление."; }
            catch (UnauthorizedAccessException) { Get<TextBlock>("SettingsStatus").Text = english ? "No permission to save appearance." : "Нет доступа для сохранения оформления."; }
        }
    }
}
