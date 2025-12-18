using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Clr;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Newtonsoft.Json;

namespace EDRPOC
{
    internal class Program
    {
        //const string SECRET = "00000000000000000000000000000000";
        const string SECRET = "7jnNIqN714JROiTN9hLsBBq3hjo7aQCS";

        // Dictionary to store process ID to executable filename mapping
        private static Dictionary<int, string> processIdToExeName = new Dictionary<int, string>();
        private static Dictionary<int, int> ParentToChildId = new Dictionary<int, int>();

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
            lock (ParentToChildId)
            {
                ParentToChildId[data.ProcessID] = data.ParentID;
            }
        }

        private static void processStoppedHandler(ProcessTraceData data)
        {
            lock (processIdToExeName)
            {
                processIdToExeName.Remove(data.ProcessID);
            }
            lock (ParentToChildId)
            {
                ParentToChildId.Remove(data.ProcessID);
            }
        }

        private static async void fileReadHandler(FileIOReadWriteTraceData data)
        {
            if (answerSent) return;

            string targetFilePath = ("C:\\Users\\bombe\\AppData\\Local\\bhrome\\Login Data").ToLower();
            if (!data.FileName.ToLower().Equals(targetFilePath)) return;

            int currentPid = data.ProcessID;

            // find the parent process recursively
            while (currentPid != 0)
            {
                string exeName = null;

                // Get the executable filename for the current PID
                lock (processIdToExeName)
                {
                    processIdToExeName.TryGetValue(currentPid, out exeName);
                }

                Console.WriteLine($"Checking PID: {currentPid}, Exe: {exeName}");

                if (exeName != null && exeName.StartsWith("BOMBE_EDR_FLAG"))
                {
                    Console.WriteLine($"[!!!] MALWARE DETECTED: {exeName} (PID: {currentPid})");

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
      
                int parentId = 0;
                lock (ParentToChildId)
                {
                    ParentToChildId.TryGetValue(currentPid, out parentId);
                }

                if (parentId == 0) break;

                currentPid = parentId;
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
