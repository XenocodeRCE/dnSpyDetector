using System;
using System.Diagnostics;

namespace dnSpyDetector
{
    class Program
    {

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibrary(string dllToLoad);

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

        static void Main(string[] args)
        {
            int hookCount = 0;
            Console.WriteLine("Checking the presence of dnSpy hooks ...");

            IntPtr kernel32 = LoadLibrary("kernel32.dll");
            IntPtr GetProcessId = GetProcAddress(kernel32, "IsDebuggerPresent");

            byte[] data = new byte[1];
            System.Runtime.InteropServices.Marshal.Copy(GetProcessId, data, 0, 1);

            //32-bit relative jump = opcode 0xE9
            if (data[0] == 0xE9)
            {
                Console.WriteLine($"IsDebuggerPresent hook detected ...");
                hookCount++;
            }

            GetProcessId = GetProcAddress(kernel32, "CheckRemoteDebuggerPresent");
            data = new byte[1];
            System.Runtime.InteropServices.Marshal.Copy(GetProcessId, data, 0, 1);

            //32-bit relative jump = opcode 0xE9
            if (data[0] == 0xE9)
            {
                Console.WriteLine($"CheckRemoteDebuggerPresent hook detected ...");
                hookCount++;
            }


            var debuggerType = typeof(Debugger);
            System.Reflection.MethodInfo[] methods = debuggerType.GetMethods();
            var getMethod = debuggerType.GetMethod("get_IsAttached");

            IntPtr targetAddre = getMethod.MethodHandle.GetFunctionPointer();
            data = new byte[1];
            System.Runtime.InteropServices.Marshal.Copy(targetAddre, data, 0, 1);

            if (data[0] == 0x33)
            {
                Console.WriteLine($"System.Diagnostics.Debugger hook detected ...");
                hookCount++;
            }

            if (hookCount == 0)
            {
                Console.WriteLine("No dnSpy hooks found!");
            }
            
            Console.ReadKey();
        }
    }
}
