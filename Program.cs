    using System;
    using System.IO;
    using System.Web;
    using System.Net;
    using System.Text;
    using System.Net.Http;
    using Newtonsoft.Json.Linq;
    using System.Threading.Tasks;

    namespace Fuzzer;

    class Program
    {
        static async Task Main(string[] args)
        {
            while (true)
            {
                Console.WriteLine("*------------------------* MENU *------------------------*");
                Console.WriteLine("Choose a function (GET, POST):");
                string function = Console.ReadLine()?.ToLower();
                switch (function)
            {
                case "get":
                    Console.WriteLine("Please enter a URL: ");
                    string url = Console.ReadLine();
                    Console.WriteLine("*------------------------* Get Request Fuzzer *------------------------*");

                    await GetFuzzer(url);
                    break;
                case "post":
                    Console.WriteLine("*------------------------* Post Request Fuzzer *------------------------*");
                    Console.WriteLine("Copy a POST request (Use Burp) and paste it here, hit enter a couple of times after posting the request:");
                    StringBuilder requestBuilder = new StringBuilder();
                    string line = string.Empty;
                    int emptyLineCount = 0;
                    while (emptyLineCount <= 1 && (line = Console.ReadLine()) != null)
                    {
                        requestBuilder.AppendLine(line);
                        if (string.IsNullOrWhiteSpace(line))
                        {
                            emptyLineCount++;
                        }
                        else
                        {
                            emptyLineCount = 0;
                        }
                    }

                    string request = requestBuilder.ToString().Trim();
                    string[] requestLines = request.Split("\r\n");
                    Console.WriteLine("[*] Starting Post Fuzzer");
                    Console.WriteLine("*------------------------*------------------------*");
                    await PostFuzzer(requestLines);
                    break;
                default:
                    Console.WriteLine("Invalid function choice. Please choose get, post, or json.");
                    break;
            }
            }
            
        }
        static async Task PostFuzzer(string[] requestLines)
        {
            string[] parms = requestLines[requestLines.Length - 1].Split('&');
            string host = string.Empty;
            string targetDirectory = string.Empty;
            var requestBuilder = new StringBuilder();
            foreach (string ln in requestLines)
            {
                if (ln.StartsWith("POST"))
                {
                    string[] postParts = ln.Split(' ');
                    targetDirectory = postParts[1];
                }
                if (ln.StartsWith("Host:"))
                    host = ln.Split(' ')[1].Replace("\r", string.Empty);
                requestBuilder.Append(ln + "\n");
            }
            string originalRequest = requestBuilder.ToString() + "\r\n";
            using (var httpClient = new HttpClient())
            {
                foreach (string parm in parms)
                {
                    string val = WebUtility.UrlEncode(parm.Split('=')[1]);
                    string modifiedRequest = string.Join("&", parms.Select(p => p.Replace("=" + parm.Split('=')[1], "=" + val + "'")));
                    HttpResponseMessage response = await httpClient.PostAsync($"http://{host}{targetDirectory}", new StringContent(modifiedRequest));
                    string responseBody = await response.Content.ReadAsStringAsync();
                    if (responseBody.Contains("error in your SQL syntax"))
                        Console.WriteLine($"[+] Parameter {parm} seems vulnerable to SQL injection with value: {val}'");
                }
            }
        }
        static async Task GetFuzzer(string url){
            string[] parms = url.Remove(0, url.IndexOf("?")+1).Split("&");
            foreach (string param in parms)
            {
                string xssUrl = url.Replace(param, param+"<xss>"); //Simple XSS - Run through all XSS combinations on all params
                string sqlUrl = url.Replace(param, param+"'");  // Simple SQLi - Run through all SQLi Combinations on all params

                // HTTP Request XSS
                HttpClient clientXSS = new HttpClient();
                HttpResponseMessage respXSS = await clientXSS.GetAsync(xssUrl);
                string xssResp = await respXSS.Content.ReadAsStringAsync();


                // HTTP Request SQLi
                HttpClient clientSQL = new HttpClient();
                HttpResponseMessage respSQL = await clientSQL.GetAsync(sqlUrl);
                string sqlResp = await respSQL.Content.ReadAsStringAsync();

                if(xssResp.Contains("<xss>"))
                {
                    Console.WriteLine($"[+] Possible XSS point found in parameter: {param}");
                }
                if(sqlResp.Contains("error in your SQL syntax"))
                {
                    Console.WriteLine($"[+] SQL Injection found in parameter: {param}");
                }
            }
        }
    }
