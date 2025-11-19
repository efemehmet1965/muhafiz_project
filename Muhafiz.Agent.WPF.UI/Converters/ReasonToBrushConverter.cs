using System;
using System.Globalization;
using System.Linq;
using System.Windows.Data;
using System.Windows.Media;

namespace Muhafiz.Agent.WPF.UI.Converters
{
    public class ReasonToBrushConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is string[] reasons && reasons.Any())
            {
                var reason = reasons[0].ToUpperInvariant();

                if (reason.Contains("IOC") || reason.Contains("YARA"))
                {
                    // Kırmızı (Tehdit)
                    return new SolidColorBrush(Color.FromArgb(50, 255, 100, 100)); 
                }
                if (reason.Contains("CANARY"))
                {
                    // Sarı (Uyarı)
                    return new SolidColorBrush(Color.FromArgb(50, 255, 255, 100));
                }
            }

            // Varsayılan (renksiz)
            return Brushes.Transparent;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
