using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Clr;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace EDRPOC
{
    internal class Program
    {
        //const string SECRET = "00000000000000000000000000000000";
        const string SECRET = "wTZafOoDdKtwfsrkKMgY0YMpcbWegMT6";

        // Dictionary to store process ID to executable filename mapping
        private static Dictionary<int, string> processIdToExeName = new Dictionary<int, string>();
        private static Dictionary<int, int> ChildToParentId = new Dictionary<int, int>();

        // Flag to ensure the answer is sent only once
        private static bool answerSent = false;

        static async Task Main(string[] args)
        {
            using (var kernelSession = new TraceEventSession(KernelTraceEventParser.KernelSessionName))
            {
                Console.CancelKeyPress += delegate (object sender, ConsoleCancelEventArgs e) { kernelSession.Dispose(); };

                kernelSession.EnableKernelProvider(
                    KernelTraceEventParser.Keywords.ImageLoad |
                    KernelTraceEventParser.Keywords.Process |
                    KernelTraceEventParser.Keywords.DiskFileIO |
                    KernelTraceEventParser.Keywords.FileIOInit |
                    KernelTraceEventParser.Keywords.FileIO
                );

                kernelSession.Source.Kernel.ProcessStart += processStartedHandler;
                kernelSession.Source.Kernel.ProcessStop += processStoppedHandler;
                kernelSession.Source.Kernel.FileIORead += fileReadHandler;

                kernelSession.Source.Process();
            }
        }

        private static void processStartedHandler(ProcessTraceData data)
        {
            lock (processIdToExeName)
            {
                processIdToExeName[data.ProcessID] = data.ImageFileName;
            }
            lock (ChildToParentId)
            {
                ChildToParentId[data.ProcessID] = data.ParentID; // Get child process id that called  by parent process
            }
        }

        private static void processStoppedHandler(ProcessTraceData data)
        {
            lock (processIdToExeName)
            {
                processIdToExeName.Remove(data.ProcessID);
            }
            lock (ChildToParentId)
            {
                ChildToParentId.Remove(data.ProcessID);
            }
        }

        private static async void fileReadHandler(FileIOReadWriteTraceData data)
        {
            // Check if the answer has already been sent
            if (answerSent) return;

            // Define the full path to the target file
            string targetFilePath = ("C:\\Users\\bombe\\AppData\\Local\\bhrome\\Login Data").ToLower();

            if (!data.FileName.ToLower().Equals(targetFilePath)) return;

            if (answerSent == true) return;
                
            int currPid = data.ProcessID;

            // Find the parent process recursively
            while (currPid != 0)
            {
                string exeName = null;

                lock (processIdToExeName)
                {
                    processIdToExeName.TryGetValue(currPid, out exeName);
                }

                Console.WriteLine("Found current process: ppid {0}, exe: {1}", currPid, exeName);

                if (exeName != null && exeName.StartsWith("BOMBE_EDR_FLAG"))
                {
                    Console.WriteLine($"[!!!] MALWARE DETECTED: {exeName} (PID: {currPid})");

                    await SendAnswerToServer(JsonConvert.SerializeObject(
                        new
                        {
                            answer = exeName,
                            secret = SECRET
                        }
                    ));

                    answerSent = true;
                    return;
                }

                int ParentPid = 0;
                lock (ChildToParentId)
                {
                    ChildToParentId.TryGetValue(currPid, out ParentPid);
                }

                if (ParentPid == 0) break;

                // Keep finding the next parent
                currPid = ParentPid;
            }
            
        }

        private static async Task SendAnswerToServer(string jsonPayload)
        {
            using (HttpClient client = new HttpClient())
            {
                StringContent content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

                try
                {
                    HttpResponseMessage response = await client.PostAsync("https://submit.bombe.top/submitEdrAns", content);
                    response.EnsureSuccessStatusCode();
                    string responseBody = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"Response: {responseBody}");
                }
                catch (HttpRequestException e)
                {
                    Console.WriteLine($"Request error: {e.Message}");
                }
            }
        }
    }
}
