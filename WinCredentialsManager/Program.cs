using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using WinCredentialsManager.Properties;

namespace WinCredentialsManager
{
    class Program
    {
        const string _defaultFilter = "VUELINGBCN";

        static void Main(string[] args)
        {
            try
            {
                if (args == null || args.Count() == 0)
                {
                    Console.WriteLine("ERROR UNKNWON METHOD");
                    Console.WriteLine();
                    Console.WriteLine(Resources.Help);
                    return;
                }

                if (!IsUserAdministrator())
                {
                    Console.WriteLine("MUST RUN WITH ADMINISTRATIVE PRIVILEGES");
                    return;
                }

                var method = args.First();

                switch (method)
                {
                    case "HELP":
                    case "?":
                    case "/?":
                        Console.WriteLine(Resources.Help);
                        break;
                    case "LISTPWD":
                        var listPwFilter = args.Count() >= 2 ? args[1] : null;
                        ViewCredentials(listPwFilter, true);
                        break;
                    case "LIST":
                        var listFilter = args.Count() >= 2 ? args[1] : null;
                        ViewCredentials(listFilter);
                        break;
                    case "MODIFY":
                        var newPassword = args.Count() >= 2 ? args[1] : null;
                        var modifyFilter = args.Count() >= 3 ? args[2] : null;
                        MassivePasswordChange(modifyFilter, newPassword);
                        break;
                    default:
                        Console.WriteLine("Error Unknwon method {0}", method);
                        break;
                }
                Console.WriteLine("Finished");                
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error while procesing");
                Console.WriteLine(ex.Message);
            }
            finally
            {
                Console.ReadKey();
            }
        }

        private static bool IsUserAdministrator()
        {
            //bool value to hold our return value
            bool isAdmin;
            try
            {
                //get the currently logged in user
                WindowsIdentity user = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(user);
                isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch (UnauthorizedAccessException ex)
            {
                isAdmin = false;
            }
            catch (Exception ex)
            {
                isAdmin = false;
            }
            return isAdmin;
        }

        private static void ViewCredentials(string userNameFilter, bool showPassword = false)
        {
            var credentials = CredentialManager.EnumerateCrendentials();
            if (!String.IsNullOrEmpty(userNameFilter))
                credentials = credentials.Where(x => (x.UserName != null && x.UserName.ToLower().Contains(userNameFilter.ToLower()))).ToList();
            foreach (var credential in credentials)
            {
                string message = String.Empty;
                if (showPassword)
                    message = String.Format("{0} {1} {2} {3}",
                        credential.CredentialType.ToString(),
                        credential.ApplicationName ?? "(none)",
                        credential.UserName ?? "(none)", 
                        credential.Password ?? "(Password not available)");
                else                   
                {
                   message = String.Format("{0} {1} {2}",
                    credential.CredentialType.ToString(),
                    credential.ApplicationName ?? "(none)",
                    credential.UserName ?? "(none)");
                }
                Console.WriteLine(message);
            }
        }

        private static void MassivePasswordChange(string userNameFilter, string newPassword)
        {
            foreach (var credential in CredentialManager.EnumerateCrendentials())
            {
                try
                {
                    Console.Write("Processing Credential {0}:{1}", credential.ApplicationName, credential.UserName);
                    if (!string.IsNullOrEmpty(credential.UserName) && credential.UserName.ToLower().Contains(userNameFilter.ToLower()))
                    {
                        CredentialManager.WriteCredential(credential.ApplicationName, credential.UserName, newPassword, credential.CredentialType);        
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.Write(" Changed!");
                        Console.ResetColor();
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.Write(" Skipped");
                        Console.ResetColor();
                    }
                    Console.WriteLine();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error Writing new configuration with {0}", credential.ApplicationName);
                    Console.WriteLine(ex.Message);
                }
            }
        }

       
    }
}
