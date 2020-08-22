using System;
namespace dnSpyDetector
{
    class Program
    {

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibrary(string dllToLoad);

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

        static void Main(string[] args) {

            Console.WriteLine("Checking the presence of dnSpy hooks ...");

            IntPtr kernel32 = LoadLibrary("kernel32.dll");
            IntPtr GetProcessId = GetProcAddress(kernel32, "IsDebuggerPresent");

            byte[] data = new byte[1];
            System.Runtime.InteropServices.Marshal.Copy(GetProcessId, data, 0, 1);

            //32-bit relative jump = opcode 0xE9
            if (data[0] == 0xE9) {
                Console.WriteLine($"IsDebuggerPresent hook detected ...");
                Console.ReadKey();
                return;
            }

            GetProcessId = GetProcAddress(kernel32, "CheckRemoteDebuggerPresent");
            data = new byte[1];
            System.Runtime.InteropServices.Marshal.Copy(GetProcessId, data, 0, 1);

            //32-bit relative jump = opcode 0xE9
            if (data[0] == 0xE9) {
                Console.WriteLine($"CheckRemoteDebuggerPresent hook detected ...");
                Console.ReadKey();
                return;
            }


            Console.ReadKey();
        }
    }
}
