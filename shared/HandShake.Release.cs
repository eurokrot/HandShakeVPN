namespace HandShake.Release
{
    public static class ProductRelease
    {
        public const string Version = "0.7-preview.10";

        public static bool MayUpgrade(string installed, string candidate)
        {
            int[] current = ReleaseOrder(installed), next = ReleaseOrder(candidate);
            if (current == null || next == null) return false;
            for (int i = 0; i < current.Length; i++)
            {
                if (next[i] != current[i]) return next[i] > current[i];
            }
            return false;
        }

        private static int[] ReleaseOrder(string value)
        {
            var match = System.Text.RegularExpressions.Regex.Match(value ?? "",
                @"^(\d+)\.(\d+)(?:\.(\d+))?(?:-preview\.(\d+))?$");
            if (!match.Success) return null;
            int[] result = new int[4];
            for (int i = 0; i < result.Length; i++)
            {
                if (!match.Groups[i + 1].Success) { result[i] = i == 3 ? int.MaxValue : 0; continue; }
                if (!int.TryParse(match.Groups[i + 1].Value, out result[i])) return null;
            }
            return result;
        }
    }
}
