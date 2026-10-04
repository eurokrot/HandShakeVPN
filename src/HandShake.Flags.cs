using System;
using System.Collections.Generic;
using System.Globalization;
using System.Windows;
using System.Windows.Media;

namespace HandShake
{
    public static class CountryFlags
    {
        private static readonly Dictionary<string, ImageSource> cache = new Dictionary<string, ImageSource>();
        public static ImageSource Get(string value)
        {
            string code = (value ?? "").ToUpperInvariant();
            if (code.Length != 2) return null;
            ImageSource existing;
            if (cache.TryGetValue(code, out existing)) return existing;
            using (var stream = typeof(CountryFlags).Assembly.GetManifestResourceStream("flags." + code.ToLowerInvariant() + ".png"))
            {
                if (stream != null)
                {
                    var bitmap = new System.Windows.Media.Imaging.BitmapImage();
                    bitmap.BeginInit(); bitmap.CacheOption = System.Windows.Media.Imaging.BitmapCacheOption.OnLoad;
                    bitmap.StreamSource = stream; bitmap.EndInit(); bitmap.Freeze(); cache[code] = bitmap;
                    return bitmap;
                }
            }
            var drawing = new DrawingGroup();
            using (var dc = drawing.Open())
            {
                Action<string, double, double, double, double> rect = delegate(string color, double x, double y, double w, double h) {
                    dc.DrawRectangle((Brush)new BrushConverter().ConvertFromString(color), null, new Rect(x, y, w, h));
                };
                rect("#FFFFFF", 0, 0, 24, 16);
                string[] stripes = code == "NL" ? new[] { "#AE1C28", "#FFFFFF", "#21468B" } :
                    code == "RU" ? new[] { "#FFFFFF", "#0039A6", "#D52B1E" } :
                    code == "DE" ? new[] { "#000000", "#DD0000", "#FFCE00" } : null;
                if (stripes != null) for (int i = 0; i < 3; i++) rect(stripes[i], 0, i * 16.0 / 3, 24, 16.0 / 3);
                else if (code == "FR" || code == "IT")
                {
                    rect(code == "FR" ? "#0055A4" : "#009246", 0, 0, 8, 16);
                    rect(code == "FR" ? "#EF4135" : "#CE2B37", 16, 0, 8, 16);
                }
                else if (code == "MT")
                {
                    rect("#CF142B", 12, 0, 12, 16);
                    rect("#AAAAAA", 3, 2, 1, 4); rect("#AAAAAA", 2, 3, 3, 1);
                }
                else if (code == "JP") dc.DrawEllipse(Brushes.Crimson, null, new Point(12, 8), 4, 4);
                else if (code == "FI") { rect("#003580", 0, 6, 24, 4); rect("#003580", 7, 0, 4, 16); }
                else if (code == "US")
                {
                    for (int i = 0; i < 13; i += 2) rect("#B22234", 0, i * 16.0 / 13, 24, 16.0 / 13);
                    rect("#3C3B6E", 0, 0, 10, 9);
                    for (int i = 0; i < 4; i++) for (int j = 0; j < 3; j++) dc.DrawEllipse(Brushes.White, null, new Point(1.5 + 2.3*i, 1.5 + 2.6*j), .4, .4);
                }
                else if (code == "GB")
                {
                    rect("#012169", 0, 0, 24, 16);
                    dc.DrawLine(new Pen(Brushes.White, 3), new Point(0, 0), new Point(24, 16));
                    dc.DrawLine(new Pen(Brushes.White, 3), new Point(0, 16), new Point(24, 0));
                    dc.DrawLine(new Pen(Brushes.Crimson, 1), new Point(0, 0), new Point(24, 16));
                    dc.DrawLine(new Pen(Brushes.Crimson, 1), new Point(0, 16), new Point(24, 0));
                    rect("#FFFFFF", 0, 5, 24, 6); rect("#FFFFFF", 9, 0, 6, 16);
                    rect("#C8102E", 0, 6, 24, 4); rect("#C8102E", 10, 0, 4, 16);
                }
                else
                {
                    rect("#24476A", 0, 0, 24, 16);
                    var text = new FormattedText(code, CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
                        new Typeface("Segoe UI"), 9, Brushes.White, 1.0);
                    dc.DrawText(text, new Point((24 - text.Width) / 2, 1));
                }
            }
            drawing.Freeze(); var result = new DrawingImage(drawing); result.Freeze(); cache[code] = result;
            return result;
        }
    }
}
