#define NETFX_35 
#undef NETFX_40

using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.Serialization;
using System.Security.Principal;
using System.Text;

// <author>José ALVAREZ</author>
// <date>16-03-11</date>
// <description>My utilities</description>
// <remarks>
//    <date>16-03-11</date> <content> Creation </content>
// </remarks>
namespace Me.Utils
{
    public static class MyString
    {
        public static string SwapChars(char[] chars)
        {
            for (int i = 0; i <= chars.Length - 2; i += 2)
            {
                Array.Reverse(chars, i, 2);
            }
            return new string(chars).Trim();
        }

    }

    public static class MyMaths
    {
        /// <summary>
        /// 1000 for disks and 1024 for memory
        /// </summary>
        /// <param name="size"></param>
        /// <param name="unit">1000 or 1024</param>
        /// <returns></returns>
        public static string GetSize(string size, int unit)
        {
            string returnValue = "";
            double sizeTO = 0;
            double sizeGO = 0;
            double sizeMO = 0;
            double sizeKO = 0;
            double sizeO = 0;


            sizeTO = double.Parse(size) / Math.Pow(unit, 4);
            sizeGO = (sizeTO - Math.Floor(sizeTO)) * 1000;
            sizeMO = (sizeGO - Math.Floor(sizeGO)) * 1000;
            sizeKO = (sizeMO - Math.Floor(sizeMO)) * 1000;
            sizeO = (sizeKO - Math.Floor(sizeKO)) * 1000;

            returnValue = TestZero(Math.Floor(sizeTO), "Tb", false);
            returnValue += TestZero(Math.Floor(sizeGO), "Gb", false);
            returnValue += " " + TestZero(Math.Floor(sizeMO), "Mb", false);
            returnValue += " " + TestZero(Math.Floor(sizeKO), "Kb", false);
            returnValue += " " + TestZero(Math.Floor(sizeO), "b", false);

            return returnValue;
        }

        private static string TestZero(double value, string unit, bool testPlur)
        {

            string returnValue = "";
            if (value > 1 && testPlur == true)
            {
                returnValue = value + " " + unit + "s";
            }
            if (value > 0)
            {
                returnValue = value + " " + unit;
            }
            return returnValue;

        }

        public static string FormatSize(Int64 taille, bool format)
        {
            string stringSize = "";
            NumberFormatInfo formatNombre = new NumberFormatInfo();

            Int64 lKBSize = 0;

            if ((taille < 1024))
            {
                if ((taille == 0))
                {
                    //zéro Octet
                    stringSize = "0";
                }
                else {
                    // < 1 Ko but not 0 byte
                    stringSize = "1";
                }
            }
            else {
                if ((format == false))
                {
                    // Format to Ko
                    lKBSize = taille / 1024;
                }
                else {
                    lKBSize = taille;
                }

                // With default format
                stringSize = lKBSize.ToString("n", formatNombre);
                // No decimal
                stringSize = stringSize.Replace(".00", "");

            }
            return stringSize + " Ko";
        }

        public static string NetworkSpeedConverter(long speed)
        {

            double tempVitesse = 0;
            string stringSpeed = "";
            NumberFormatInfo formatNombre = new NumberFormatInfo();

            if ((speed < 1000))
            {
                // < 1 G Hz
                stringSpeed = speed.ToString() + " M Hz";
            }
            else {
                // to Giga Hz
                tempVitesse = speed / 1000;

                stringSpeed = tempVitesse.ToString() + " G Hz";
            }
            return stringSpeed;

        }

    }

    public static class MyVersions
    {
        public static string WmiGetVersion()
        {
            string version = string.Empty;
            try
            {
                ManagementObjectSearcher searcher =
                    new ManagementObjectSearcher("root\\CIMV2",
                    "SELECT * FROM Win32_OperatingSystem");

                foreach (ManagementObject queryObj in searcher.Get())
                {
                    version = queryObj["Version"].ToString();
                }
            }
            catch (ManagementException)
            {
                throw;
            }
            return version;
        }

        public static string GetVersionFromRegistry()
        {
            string returnedData = string.Empty;

            // Opens the registry key for the .NET Framework entry.
            using (RegistryKey ndpKey =
                RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, "").
                OpenSubKey(@"SOFTWARE\Microsoft\NET Framework Setup\NDP\"))
            {
                // As an alternative, if you know the computers you will query are running .NET Framework 4.5 
                // or later, you can use:
                // using (RegistryKey ndpKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, 
                // RegistryView.Registry32).OpenSubKey(@"SOFTWARE\Microsoft\NET Framework Setup\NDP\"))
                foreach (string versionKeyName in ndpKey.GetSubKeyNames())
                {
                    if (versionKeyName.StartsWith("v"))
                    {

                        RegistryKey versionKey = ndpKey.OpenSubKey(versionKeyName);
                        string name = (string)versionKey.GetValue("Version", "");
                        string sp = versionKey.GetValue("SP", "").ToString();
                        string install = versionKey.GetValue("Install", "").ToString();
                        if (install == "") //no install info, must be later.
                        {
                            //Console.WriteLine(versionKeyName + "  " + name);
                            returnedData += string.Format("{0} {1}\r\n", versionKeyName, name);
                        }
                        else
                        {
                            if (sp != "" && install == "1")
                            {
                                //Console.WriteLine(versionKeyName + "  " + name + "  SP" + sp);
                                returnedData += string.Format("{0} {1} SP{2}\r\n", versionKeyName, name, sp);
                            }

                        }
                        if (name != "")
                        {
                            continue;
                        }
                        foreach (string subKeyName in versionKey.GetSubKeyNames())
                        {
                            RegistryKey subKey = versionKey.OpenSubKey(subKeyName);
                            name = (string)subKey.GetValue("Version", "");
                            if (name != "")
                                sp = subKey.GetValue("SP", "").ToString();
                            install = subKey.GetValue("Install", "").ToString();
                            if (install == "") //no install info, must be later.
                            {
                                //Console.WriteLine(versionKeyName + "  " + name);
                                returnedData += string.Format("{0} {1}\r\n", versionKeyName, name);
                            }
                            else
                            {
                                if (sp != "" && install == "1")
                                {
                                    //Console.WriteLine("  " + subKeyName + "  " + name + "  SP" + sp);
                                    returnedData += string.Format(" {0} {1} SP{2}\r\n", versionKeyName, name, sp);
                                }
                                else if (install == "1")
                                {
                                    //Console.WriteLine("  " + subKeyName + "  " + name);
                                    returnedData += string.Format(" {0} {1}\r\n", versionKeyName, name);
                                }
                            }
                        }
                    }
                }
            }
            return returnedData;
        }

        public static string FrameWorkVersion()
        {
            string version = Assembly
                     .GetExecutingAssembly()
                     .GetReferencedAssemblies()
                     .Where(x => x.Name == "System.Core").First().Version.ToString();
            return version;
        }

        private static string FrameWorkVersionAssembly(string assemblyName)
        {
            string version = string.Empty;

            try
            {

                version = Assembly
                 .LoadFrom(assemblyName)
                 .GetReferencedAssemblies()
                 .Where(x => x.Name == "System.Core").First().Version.ToString();

            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.Message);
                throw;
            }
            return version;
        }

        private static string CLRForThisAssembly(string assemblyName)
        {
            string version = string.Empty;

            try
            {
                version = Assembly
                 .LoadFrom(assemblyName).ImageRuntimeVersion;

            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.Message);
                throw;
            }
            return version;
        }

    }

    public static class MyTrace
    {
        public static TraceSwitch MyTraceInit(string displayName, string description, string defaultSwitchValue)
        {
            TraceSwitch myTraceSwitch = null;

            myTraceSwitch =
                new TraceSwitch(displayName, description, defaultSwitchValue);
            Trace.AutoFlush = true;

            Trace.WriteLine("");
            Trace.WriteLine("************************************************************************************************************");
            Trace.WriteLine(DateTime.Now.ToString());
            Trace.WriteLine("");
            Trace.WriteLine("TraceSwitch.DisplayName: " + myTraceSwitch.DisplayName);
            Trace.WriteLine("TraceSwitch.Description: " + myTraceSwitch.Description);
            Trace.WriteLine("TraceSwitch.Level: " + myTraceSwitch.Level);
            Trace.WriteLine("");

            return myTraceSwitch;
        }

        public static void MyTraceBegin(TraceSwitch traceswitch, string sourceAssembly, string message = "")
        {
            Trace.WriteLineIf(traceswitch.TraceVerbose, ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
            Trace.WriteLineIf(traceswitch.TraceVerbose, string.Format("{0}: BEGIN BY {1} : {2}", DateTime.Now, sourceAssembly, message));
        }

        public static void MyTraceIf(TraceSwitch traceswitch, string sourceAssembly, string sourceMethod, string message)
        {
            Trace.WriteLineIf(traceswitch.TraceVerbose, string.Format("{0}: {1}-{2}(): {3}", DateTime.Now, sourceAssembly, sourceMethod, message));
        }

        public static void MyTraceEnd(TraceSwitch traceswitch, string sourceAssembly, string message = "")
        {
            Trace.WriteLineIf(traceswitch.TraceVerbose, string.Format("{0}: END BY {1} : {2}", DateTime.Now, sourceAssembly, message));
            Trace.WriteLineIf(traceswitch.TraceVerbose, ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");

        }

    }

    public static class MyWmi
    {
        public static string DeviceInformation(string stringIn)
        {
            StringBuilder StringBuilder1 = new StringBuilder(string.Empty);
            try
            {
                ManagementClass ManagementClass1 = new ManagementClass(stringIn);
                //Create a ManagementObjectCollection to loop through
                ManagementObjectCollection ManagemenobjCol = ManagementClass1.GetInstances();
                //Get the properties in the class
                PropertyDataCollection properties = ManagementClass1.Properties;
                foreach (ManagementObject obj in ManagemenobjCol)
                {
                    foreach (PropertyData property in properties)
                    {
                        try
                        {
                            StringBuilder1.AppendLine(property.Name + ":  " + obj.Properties[property.Name].Value.ToString());
                        }
                        catch
                        {
                            //Add codes to manage more informations
                        }
                    }
                    StringBuilder1.AppendLine();
                }
            }
            catch
            {
                //Win 32 Classes Which are not defined on client system
            }
            return StringBuilder1.ToString();
        }

        public static WmiDonneesDisque GetSerialNumberWmi(int index)
        {
            WmiDonneesDisque dd = new WmiDonneesDisque();

            try
            {
                ManagementObjectSearcher objSearcherMedia = new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_PhysicalMedia");
                foreach (ManagementObject objQueryMedia in objSearcherMedia.Get())
                {
                    dd.DeviceID = objQueryMedia["Tag"].ToString();
                    if (dd.DeviceID.Contains(index.ToString()))
                    {
                        dd.NumeroSerie = objQueryMedia["SerialNumber"] != null ? objQueryMedia["SerialNumber"].ToString().Trim() : "";
                        if (dd.NumeroSerie != string.Empty)
                        {
                            ManagementObjectSearcher objSearcherDrive = new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_DiskDrive WHERE DeviceID='\\\\\\\\.\\\\" + dd.DeviceID.Substring(4) + "'");
                            foreach (ManagementObject objQueryDrive in objSearcherDrive.Get())
                            {
                                dd.Modele = objQueryDrive["Model"].ToString();
                                dd.Type = objQueryDrive["InterfaceType"].ToString();
                            }
                            break;
                        }

                    }
                }
            }
            catch (Exception)
            {
                throw;
            }
            return dd;
        }

        public class WmiDonneesDisque
        {
            public string DeviceID;
            public string NumeroSerie;
            public string Modele;
            public string Type;
        }

    }

    public static class MyFiles
    {

        /// <summary>
        /// This function is used to check specified file being used or not
        /// http://dotnet-assembly.blogspot.fr/2012/10/c-check-file-is-being-used-by-another.html
        /// </summary>
        /// <param name="file">FileInfo of required file</param>
        /// <returns>If that specified file is being processed 
        /// or not found is return true</returns>
        public static Boolean IsFileLocked(string file)
        {
            FileStream stream = null;
            try
            {
                //Don't change FileAccess to ReadWrite, 
                //because if a file is in readOnly, it fails.
                stream = File.Open(file, FileMode.Open, FileAccess.Read, FileShare.None);
            }
            catch (IOException)
            {
                //the file is unavailable because it is:
                //still being written to
                //or being processed by another thread
                //or does not exist (has already been processed)
                return true;
            }
            finally
            {
                if (stream != null)
                    stream.Close();
            }
            //file is not locked
            return false;
        }

    }

    public static class MyCulture
    {
        public static string GetCulture()
        {
            return System.Threading.Thread.CurrentThread.CurrentCulture.ToString();
        }
        public static string GetUiCulture()
        {
            return System.Threading.Thread.CurrentThread.CurrentUICulture.ToString();
        }

    }

    public static class MyNetwork
    {
        /// <summary>
        /// 
        /// </summary>
        /// <returns>ip, speed or null, null</returns>
        private static string[] IsNetworkAvailableWithValues()
        {
            string[] returnValues = new string[2];

            // only recognizes changes related to Internet adapters
            if (NetworkInterface.GetIsNetworkAvailable())
            {
                // however, this will include all adapters
                NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();
                foreach (NetworkInterface face in interfaces)
                {
                    // filter so we see only Internet adapters
                    if (face.OperationalStatus == OperationalStatus.Up)
                    {
                        if ((face.NetworkInterfaceType != NetworkInterfaceType.Tunnel) &&
                            (face.NetworkInterfaceType != NetworkInterfaceType.Loopback))
                        {
                            IPv4InterfaceStatistics statistics = face.GetIPv4Statistics();

                            // all testing seems to prove that once an interface comes online
                            // it has already accrued statistics for both received and sent...

                            if ((statistics.BytesReceived > 0) &&
                                (statistics.BytesSent > 0))
                            {
                                returnValues[0] = face.GetIPProperties().UnicastAddresses[0].Address.ToString();
                                returnValues[1] = face.Speed.ToString();
                                return returnValues;
                            }
                        }
                    }
                }
            }

            return returnValues;
        }

        private static bool IsNetworkAvailable()
        {

            // only recognizes changes related to Internet adapters
            if (NetworkInterface.GetIsNetworkAvailable())
            {
                // however, this will include all adapters
                NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();
                foreach (NetworkInterface face in interfaces)
                {
                    // filter so we see only Internet adapters
                    if (face.OperationalStatus == OperationalStatus.Up)
                    {
                        if ((face.NetworkInterfaceType != NetworkInterfaceType.Tunnel) &&
                            (face.NetworkInterfaceType != NetworkInterfaceType.Loopback))
                        {
                            IPv4InterfaceStatistics statistics = face.GetIPv4Statistics();

                            // all testing seems to prove that once an interface comes online
                            // it has already accrued statistics for both received and sent...

                            if ((statistics.BytesReceived > 0) &&
                                (statistics.BytesSent > 0))
                            {
                                return true;
                            }
                        }
                    }
                }
            }

            return false;

        }

        private static string GetIP()
        {
            string returnedIp = "";

            List<IPAddress> localAddresses = new List<IPAddress>();

            foreach (IPAddress ipAddress in Dns.GetHostEntry(Dns.GetHostName()).AddressList)
            {
                if (ipAddress.AddressFamily == AddressFamily.InterNetwork) // filter out ipv4
                {

                    if (!ipAddress.IsIPv6LinkLocal)
                    {
                        if (!(ipAddress.ToString().Substring(0, 3) == "169"))
                        {
                            localAddresses.Add(ipAddress);
                            returnedIp = ipAddress.ToString();
                        }
                    }

                }
            }
            return returnedIp;
        }


    }

    public static class MySystem
    {

        // function to display its name
        private static void WhatsMyName()
        {
            StackFrame stackFrame = new StackFrame();
            MethodBase methodBase = stackFrame.GetMethod();
            //Console.WriteLine(methodBase.Name); // Displays “WhatsmyName”
            WhoCalledMe();
        }

        // Function to display parent function
        private static void WhoCalledMe()
        {
            StackTrace stackTrace = new StackTrace();
            StackFrame stackFrame = stackTrace.GetFrame(1);
            MethodBase methodBase = stackFrame.GetMethod();
            // Displays “WhatsmyName”
            //Console.WriteLine(" Parent Method Name {0} ", methodBase.Name);
        }

        /// <summary>
        /// 
        /// Return caller method name
        /// http://www.codeproject.com/Articles/7964/Logging-method-name-in-NET
        /// </summary>
        public static string MethodName()
        {
            StackTrace stackTrace = new StackTrace();
            StackFrame stackFrame = stackTrace.GetFrame(1);
            MethodBase methodBase = stackFrame.GetMethod();
            return methodBase.Name;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public static bool IsAdmin()
        {
            return (new WindowsPrincipal(WindowsIdentity.GetCurrent())).IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static string SystemInformation()
        {
            StringBuilder StringBuilder1 = new StringBuilder(string.Empty);
            try
            {
                StringBuilder1.AppendFormat("Operation System:  {0}\r\n", Environment.OSVersion);
#if NETFX_40
                if (Environment.Is64BitOperatingSystem)
                    StringBuilder1.AppendFormat("\t\t  64 Bit Operating System\r\n");
                else
#endif
                StringBuilder1.AppendFormat("\t\t  32 Bit Operating System\r\n");

                StringBuilder1.AppendFormat("SystemDirectory:  {0}\r\n", Environment.SystemDirectory);
                StringBuilder1.AppendFormat("ProcessorCount:  {0}\r\n", Environment.ProcessorCount);
                StringBuilder1.AppendFormat("UserDomainName:  {0}\r\n", Environment.UserDomainName);
                StringBuilder1.AppendFormat("UserName: {0}\r\n", Environment.UserName);
                //Drives
                StringBuilder1.AppendFormat("LogicalDrives:\r\n");
                foreach (System.IO.DriveInfo DriveInfo1 in System.IO.DriveInfo.GetDrives())
                {
                    try
                    {
                        StringBuilder1.AppendFormat("\t Drive: {0}\r\n\t\t VolumeLabel: {1}\r\n\t\t DriveType: {2}\r\n\t\t DriveFormat: {3}\r\n\t\t TotalSize: {4}\r\n\t\t AvailableFreeSpace: {5}\r\n",
                            DriveInfo1.Name, DriveInfo1.VolumeLabel, DriveInfo1.DriveType, DriveInfo1.DriveFormat,
                            MyMaths.GetSize(DriveInfo1.TotalSize.ToString(), 1000),
                            MyMaths.GetSize(DriveInfo1.AvailableFreeSpace.ToString(), 1000));
                    }
                    catch
                    {
                    }
                }
                var wmiObject = new ManagementObjectSearcher("select * from Win32_OperatingSystem");

                // WMI result is in Kb ==> * 1000
                var memoryValues = wmiObject.Get().Cast<ManagementObject>().Select(mo => new
                {
                    FreePhysicalMemory = Double.Parse(mo["FreePhysicalMemory"].ToString()) * 1024,
                    TotalVisibleMemorySize = Double.Parse(mo["TotalVisibleMemorySize"].ToString()) * 1024
                }).FirstOrDefault();

                StringBuilder1.AppendFormat("\r\nTotal Visible Memory Size: {0}\r\n", MyMaths.GetSize(memoryValues.TotalVisibleMemorySize.ToString(), 1024));
                StringBuilder1.AppendFormat("Free Physical Memory: {0}\r\n", MyMaths.GetSize(memoryValues.FreePhysicalMemory.ToString(), 1024));
                StringBuilder1.AppendFormat("WorkingSet: {0}\r\n", MyMaths.GetSize(Environment.WorkingSet.ToString(), 1024));
#if NETFX_40

                StringBuilder1.AppendFormat("\r\nSystemPageSize: {0}\r\n", MyMaths.GetSize(Environment.SystemPageSize.ToString(), 1024));
#endif
                StringBuilder1.AppendFormat("\r\nVersion:  {0}", Environment.Version);
            }
            catch
            {
            }
            return StringBuilder1.ToString();
        }

    }

}

// <author>José ALVAREZ</author>
// <date>16-03-11</date>
// <description>Errors and messages management with localization</description>
// <remarks>
//    <date>16-03-11</date> <content> Creation </content>
// </remarks>
namespace Me.Utils
{
    public static class MeError
    {
        public class MeException : Exception
        {

            public MeException()
            {
            }

            public MeException(string message)
                : base(message)
            {
            }

            public MeException(string message, Exception inner)
                : base(message, inner)
            {
            }

            // This constructor is needed for serialization.
            protected MeException(SerializationInfo info, StreamingContext context)
            {
                // Add implementation.
            }

            private MeError.MeErrorCode _meErrorCode;
            private MeError.MeMessageCode _meMessageCode;

            public MeError.MeErrorCode MeErrorCode
            {
                get
                {
                    return this._meErrorCode;
                }

                set
                {
                    this._meErrorCode = value;
                }
            }

            public MeError.MeMessageCode MeMessageCode
            {
                get
                {
                    return this._meMessageCode;
                }

                set
                {
                    this._meMessageCode = value;
                }
            }

        }

        // http://blog.spontaneouspublicity.com/associating-strings-with-enums-in-c
        public static MeException CreateMeException(MeErrorCode code)
        {
            Trace.TraceError("{0} {1}:{2} MessageError: \"{3}\"", DateTime.Now, code, (int)code, GetEnumDescription(code));
            return new MeException(GetEnumDescription(code)) { MeErrorCode = code };
        }

        public static MeException CreateMeException(MeMessageCode code)
        {
            Trace.TraceInformation("{0} {1}:{2} MessageInfo: \"{3}\"", DateTime.Now, code, (int)code, GetEnumDescription(code));
            return new MeException(GetEnumDescription(code)) { MeMessageCode = code };
        }

        /// <summary>
        /// Example:
        /// throw MeError.CreateMeException(MeError.MeErrorCode.ERROR_FileNotFound);
        /// </summary>
        public enum MeErrorCode
        {
            [Description("File not found.")]
            ERROR_FileNotFound = 10000,
            [Description("File corrupted.")]
            ERROR_FileCorrupted,
        }

        /// <summary>
        /// Solution specifics messages and codes
        /// Examples:
        /// throw MeError.CreateMeException(MeError.MeMessageCode.MESSAGE_Unauthorized);
        /// return MeError.MeMessageCode.MESSAGE_Success;
        /// </summary>
        public enum MeMessageCode
        {
            [Description("Success.")]
            MESSAGE_Success = 20000,

        }

        /// <summary>
        /// Solution specifics messages and codes
        /// Examples:
        /// throw MeError.CreateMeException(MeError.MeMessageCode.MESSAGE_Unauthorized);
        /// return MeError.MeMessageCode.MESSAGE_Success;
        /// </summary>
        public enum LocalizedMessageCode
        {
            //[LocalizedEnum("MESSAGE_Success", NameResourceType = typeof(Me.Me.Common.Resources))]
            //MESSAGE_Success = 20000,
        }

        /// <summary>
        /// 
        /// </summary>
        public class LocalizedEnumAttribute : DescriptionAttribute
        {
            private PropertyInfo _nameProperty;
            private Type _resourceType;

            public LocalizedEnumAttribute(string displayNameKey)
                : base(displayNameKey)
            {

            }

            public Type NameResourceType
            {
                get
                {
                    return _resourceType;
                }
                set
                {
                    _resourceType = value;

                    _nameProperty = _resourceType.GetProperty(this.Description, BindingFlags.Static | BindingFlags.Public);
                }
            }

            public override string Description
            {
                get
                {
                    //check if nameProperty is null and return original display name value
                    if (_nameProperty == null)
                    {
                        return base.Description;
                    }

                    return (string)_nameProperty.GetValue(_nameProperty.DeclaringType, null);
                }
            }
        }

        // http://blog.spontaneouspublicity.com/associating-strings-with-enums-in-c
        public static string GetEnumDescription(Enum value)
        {

            FieldInfo fi = value.GetType().GetField(value.ToString());

            DescriptionAttribute[] attributes =
                (DescriptionAttribute[])fi.GetCustomAttributes(typeof(DescriptionAttribute), false);

            if (attributes != null && attributes.Length > 0)
                return attributes[0].Description;
            else
                return value.ToString();

        }

        public static string PrintMessage(MeMessageCode code)
        {
            return string.Format("{0} {1}:{2} MessageInfo: \"{3}\"", DateTime.Now, code, (int)code, GetEnumDescription(code));
        }

    }

    /// <summary>
    /// Attributs localization extension method
    /// http://stackoverflow.com/questions/569298/localizing-enum-descriptions-attributes
    /// </summary>
    public static class LocalizedEnumExtender
    {
        public static string GetLocalizedEnumDescription(this Enum @enum)
        {
            if (@enum == null)
                return null;

            string description = @enum.ToString();

            FieldInfo fieldInfo = @enum.GetType().GetField(description);
            DescriptionAttribute[] attributes = (DescriptionAttribute[])fieldInfo.GetCustomAttributes(typeof(DescriptionAttribute), false);

            if (attributes.Any())
                return attributes[0].Description;

            return description;
        }
    }

}