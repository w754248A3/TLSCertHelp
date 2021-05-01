using LeiKaiFeng.X509Certificates;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace TLSCertHelp
{
    sealed class CertInfo
    {
        public CertInfo(int day, int keySize, string caName, string subCertName)
        {
            Day = day;
            KeySize = keySize;
            CaName = caName ?? throw new ArgumentNullException(nameof(caName));
            SubCertName = subCertName ?? throw new ArgumentNullException(nameof(subCertName));
        }

        public int Day { get; }

        public int KeySize { get; }


        public string CaName { get; }


        public string SubCertName { get; }


    }

    class Program
    {
        const string INFO_FILE = "info.txt";

        const string HOSTS_FILE = "hosts.txt";

        static string GetBasePath()
        {
            return AppDomain.CurrentDomain.BaseDirectory;
        }

        static string GetSaveCertPath()
        {
            var path = Path.Combine(GetBasePath(), "conf");

            Directory.CreateDirectory(path);

            return path;
        }

        static string GetInfoFilePath()
        {
            return Path.Combine(GetBasePath(), INFO_FILE);
        }

        static string GetHostsFilePath()
        {
            return Path.Combine(GetBasePath(), HOSTS_FILE);
        }

        static CertInfo CreateCertInfo()
        {
            
            var vs = File.ReadAllText(GetInfoFilePath(), Encoding.UTF8)
                .Split(new string[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries)
                .Where(s => s.StartsWith("#") == false)
                .Select((s) => s.Trim())
                .ToArray();


            return new CertInfo(
                int.Parse(vs[0]),
                int.Parse(vs[1]),
                vs[2],
                vs[3]);
           
        }

        static string[] CreateHosts()
        {
            
            return File.ReadAllText(GetHostsFilePath(), Encoding.UTF8)
                .Split(new string[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries)
                .Where(s => s.StartsWith("#") == false)
                .Select(s => s.Trim())
                .ToArray();
        }

        static string CreateText(params string[] vs)
        {
            return string.Join(Environment.NewLine, vs);
        }

        static void SaveCa(X509Certificate2 certificate2)
        {
            var pfxPath = Path.Combine(GetSaveCertPath(), "ca.pfx");

            var certPath = Path.Combine(GetSaveCertPath(), "ca.cer");



            File.WriteAllBytes(pfxPath, certificate2.Export(X509ContentType.Pfx));


            File.WriteAllBytes(certPath, certificate2.Export(X509ContentType.Cert));


        }

        static void SaveTlsPem(X509Certificate2 certificate2)
        {
            var pemPath = Path.Combine(GetSaveCertPath(), "tls.pem");

            var keyPath = Path.Combine(GetSaveCertPath(), "tls.key");



            var pem = TLSBouncyCastleHelper.CreatePem.AsPem(certificate2);


            var key = TLSBouncyCastleHelper.CreatePem.AsKey(certificate2);






            File.WriteAllBytes(pemPath, pem);


            File.WriteAllBytes(keyPath, key);


        }

        static void SaveTls(X509Certificate2 certificate2)
        {
            var pfxPath = Path.Combine(GetSaveCertPath(), "tls.pfx");

            var certPath = Path.Combine(GetSaveCertPath(), "tls.cer");





            File.WriteAllBytes(pfxPath, certificate2.Export(X509ContentType.Pfx));


            File.WriteAllBytes(certPath, certificate2.Export(X509ContentType.Cert));


        }

        static void Main(string[] args)
        {

            if (File.Exists(GetInfoFilePath()) == false ||
                File.Exists(GetHostsFilePath()) == false)
            {


                if (File.Exists(GetInfoFilePath()) == false)
                {

                    File.WriteAllText(
                        GetInfoFilePath(),
                        CreateText(
                            "#开头的是注释",
                            "#按位置决定参数的意义",
                            "#Day",
                            "#KeySize",
                            "#CaName",
                            "#SubCertName"),
                        Encoding.UTF8);


                }


                if (File.Exists(GetHostsFilePath()) == false)
                {
                    File.WriteAllText(GetHostsFilePath(), "", Encoding.UTF8);
                }

                Console.WriteLine("已创建配置文件请编辑后继续运行");
                Console.ReadLine();
                return;
            }




            var certInfo = CreateCertInfo();

            var hosts = CreateHosts();


            var caCert = TLSBouncyCastleHelper.GenerateCA(
                certInfo.CaName,
                certInfo.KeySize,
                certInfo.Day);


            var tlsCert = TLSBouncyCastleHelper.GenerateTls(
                CaPack.Create(caCert),
                certInfo.SubCertName,
                certInfo.KeySize,
                certInfo.Day,
                hosts);



            SaveCa(caCert);

            SaveTls(tlsCert);

            SaveTlsPem(tlsCert);



        }
    }
}
