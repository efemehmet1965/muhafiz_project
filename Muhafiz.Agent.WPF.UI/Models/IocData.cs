
using System.Collections.Generic;

namespace Muhafiz.Agent.WPF.UI.Models
{
    public class IocEntry
    {
        public string Value { get; set; } = string.Empty;
    }

    public class HashesFileContent
    {
        public List<string> malicious_hashes { get; set; } = new List<string>();
    }

    public class UrlsFileContent
    {
        public List<string> blocked_hosts { get; set; } = new List<string>();
        public List<string> blocked_paths { get; set; } = new List<string>();
        public List<string> ioc_ips { get; set; } = new List<string>();
    }
}
