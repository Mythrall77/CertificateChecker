using System;
using System.Collections.Generic;
using System.Configuration; // Required for AppSettings
using System.IO;
using System.Linq; // Required for Linq operations like OrderBy, Any
using System.Net; // Required for NetworkCredential, ServicePointManager, WebUtility
using System.Net.Mail; // Required for SmtpClient, MailMessage
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text; // Required for Encoding
using System.Text.RegularExpressions;
// Removed: using System.Web;

namespace CertificateChecker
{
    // Simple class to hold certificate details for processing and display
    class CertificateInfo
    {
        public string Subject { get; set; }
        public string FriendlyName { get; set; }
        public DateTime ExpiryDate { get; set; }
        public int DaysLeft { get; set; }
        public string Thumbprint { get; set; }
        public string StoreLocationName { get; set; } // e.g., "LocalMachine"
        public string StoreNameInput { get; set; } // The actual string name used, e.g., "My", "Root", "RemoteDesktop"
        public string StorePath { get; set; } // e.g., Cert:\LocalMachine\My
    }

    // Simple class to hold email configuration from App.config
    class EmailConfig
    {
        public string SmtpServer { get; set; }
        public int SmtpPort { get; set; }
        public bool EnableSsl { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string FromAddress { get; set; }
        public List<string> ToRecipients { get; set; } = new List<string>();
    }

    class Program
    {
        // Constants for consistent output formatting
        private const int SubjectWidth = 45;
        private const int FriendlyNameWidth = 25;
        private const int ExpiresOnWidth = 12;
        private const int DaysLeftWidth = 10;
        private const int ThumbprintWidth = 42;
        // Adjust total width based on included columns and separators (|) - Estimate includes PS Cmd space
        private const int TotalConsoleWidth = SubjectWidth + FriendlyNameWidth + ExpiresOnWidth + DaysLeftWidth + ThumbprintWidth + 16 + 60;

        static int Main(string[] args)
        {
            // --- Default Values ---
            StoreLocation storeLocation = StoreLocation.LocalMachine;
            string storeNameInput = "My"; // Use string, default to "My"

            string filterPattern = null;
            Regex filterRegex = null;
            string thumbprintToDelete = null;
            bool showHelp = false;
            bool forceDeletePrompt = false;
            int? expireWithinDays = null;
            bool showExpiredOnly = false;
            bool emailNotify = false;

            // --- Argument Parsing ---
            try
            {
                for (int i = 0; i < args.Length; i++)
                {
                    string arg = args[i].ToLowerInvariant();
                    string nextArg = (i + 1 < args.Length) ? args[i + 1] : null;

                    switch (arg)
                    {
                        case "--store-location":
                        case "-sl":
                            if (nextArg != null)
                            {
                                if (!Enum.TryParse(nextArg, true, out storeLocation))
                                {
                                    Console.Error.WriteLine($"ERROR: Invalid StoreLocation '{nextArg}'. Valid: {string.Join(", ", Enum.GetNames(typeof(StoreLocation)))}");
                                    return 1;
                                }
                                i++;
                            }
                            else { goto MissingValueError; }
                            break;

                        case "--store-name":
                        case "-sn":
                            if (nextArg != null)
                            {
                                storeNameInput = nextArg; // Assign string directly
                                i++;
                            }
                            else { goto MissingValueError; }
                            break;

                        case "--filter":
                        case "-f":
                            if (nextArg != null)
                            {
                                filterPattern = nextArg;
                                try { filterRegex = new Regex(filterPattern, RegexOptions.IgnoreCase | RegexOptions.Compiled); }
                                catch (ArgumentException ex) { Console.Error.WriteLine($"ERROR: Invalid Regex pattern '{filterPattern}': {ex.Message}"); return 1; }
                                i++;
                            }
                            else { goto MissingValueError; }
                            break;

                        case "--delete":
                        case "-d":
                            if (nextArg != null)
                            {
                                thumbprintToDelete = nextArg.Trim().ToUpperInvariant().Replace(" ", "");
                                if (string.IsNullOrWhiteSpace(thumbprintToDelete) || thumbprintToDelete.Length != 40 || !Regex.IsMatch(thumbprintToDelete, "^[0-9A-F]{40}$"))
                                {
                                    Console.Error.WriteLine($"ERROR: Invalid Thumbprint format provided for --delete. Expected 40 hex characters."); return 1;
                                }
                                i++;
                            }
                            else { goto MissingValueError; }
                            break;

                        case "--expire-within":
                        case "-ew":
                            if (nextArg != null && int.TryParse(nextArg, out int days) && days >= 0)
                            {
                                expireWithinDays = days; i++;
                            }
                            else { Console.Error.WriteLine($"ERROR: Invalid or missing non-negative integer value for {arg}."); PrintUsage(); return 1; }
                            break;

                        case "--expired":
                            showExpiredOnly = true; break;
                        case "--email-notify":
                        case "-en":
                            emailNotify = true; break;
                        case "--yes":
                        case "-y":
                            forceDeletePrompt = true; break;
                        case "--help":
                        case "-h":
                        case "/?":
                            showHelp = true; break;

                        default:
                            Console.Error.WriteLine($"ERROR: Unknown argument '{args[i]}'"); PrintUsage(); return 1;
                    }
                    continue; // Process next argument

                    MissingValueError:
                    Console.Error.WriteLine($"ERROR: Missing value for argument '{arg}'."); PrintUsage(); return 1;
                }

                // --- Argument Validation ---
                if (expireWithinDays.HasValue && showExpiredOnly)
                {
                    Console.Error.WriteLine("ERROR: Cannot use --expire-within and --expired options together."); PrintUsage(); return 1;
                }
                if (!string.IsNullOrEmpty(thumbprintToDelete) && (expireWithinDays.HasValue || showExpiredOnly || emailNotify))
                {
                    Console.WriteLine("Warning: Date filters (--expire-within, --expired) and --email-notify are ignored when --delete is specified.");
                    expireWithinDays = null; showExpiredOnly = false; emailNotify = false;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"ERROR parsing arguments: {ex.Message}"); PrintUsage(); return 1;
            }

            // --- Debug Parsed Arguments ---
            Console.WriteLine($"---> DEBUG: StoreLocation='{storeLocation}', StoreName='{storeNameInput}', ExpireWithin='{expireWithinDays}', ExpiredOnly='{showExpiredOnly}', EmailNotify='{emailNotify}', DeleteThumbprint='{thumbprintToDelete}', Filter='{filterPattern}' <---");

            if (showHelp) { PrintUsage(); return 0; }

            // --- Set TLS Protocols for SMTP ---
            try
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
                Console.WriteLine("--> DEBUG: Set SecurityProtocol to Tls12 | Tls11 | Tls.");
            }
            catch (NotSupportedException ex)
            {
                Console.Error.WriteLine($"Warning: Could not explicitly set desired TLS protocols (NotSupportedException: {ex.Message}). Using system defaults.");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Warning: Error setting SecurityProtocol: {ex.Message}. Using system defaults.");
            }

            // --- Mode Selection ---
            if (!string.IsNullOrEmpty(thumbprintToDelete))
            {
                return HandleDeletion(storeLocation, storeNameInput, thumbprintToDelete, forceDeletePrompt);
            }
            else
            {
                return ListAndNotifyCertificates(storeLocation, storeNameInput, filterRegex, filterPattern, expireWithinDays, showExpiredOnly, emailNotify);
            }
        } // End Main

        // --- Listing and Notification Mode ---
        static int ListAndNotifyCertificates(StoreLocation storeLocation, string storeNameInput, Regex filterRegex, string filterPattern,
                                            int? expireWithinDaysFilter, bool showExpiredOnly, bool emailNotify)
        {
            X509Store store = null;
            List<CertificateInfo> certificatesToDisplay = new List<CertificateInfo>();
            List<CertificateInfo> certificatesExpiringSoonForEmail = new List<CertificateInfo>();
            int defaultEmailNotifyDays = 30;
            EmailConfig emailConfig = null;

            if (emailNotify)
            {
                emailConfig = ReadEmailConfiguration(ref defaultEmailNotifyDays);
                if (emailConfig == null)
                {
                    Console.Error.WriteLine("Email notification aborted due to configuration errors. Only listing will proceed.");
                    emailNotify = false; // Disable email sending
                }
            }
            int emailCheckThresholdDays = expireWithinDaysFilter ?? defaultEmailNotifyDays;

            try
            {
                Console.WriteLine($"\nAccessing Certificate Store: {storeLocation}/{storeNameInput}");
                if (filterRegex != null) { Console.WriteLine($"Applying Filter (Regex): '{filterPattern}' on Subject or Friendly Name"); }
                if (expireWithinDaysFilter.HasValue) { Console.WriteLine($"Filtering: Show certificates expiring in {expireWithinDaysFilter} days or less (excluding expired)."); }
                if (showExpiredOnly) { Console.WriteLine($"Filtering: Show ONLY expired certificates."); }
                if (emailNotify) { Console.WriteLine($"Email Notification: Enabled (Threshold: {emailCheckThresholdDays} days)"); }
                Console.WriteLine(new string('-', TotalConsoleWidth));

                store = new X509Store(storeNameInput, storeLocation);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                if (store.Certificates.Count == 0)
                {
                    Console.WriteLine("No certificates found in this store."); return 0;
                }

                DateTime nowUtc = DateTime.UtcNow;
                string storePathBase = $"Cert:\\{storeLocation}\\{storeNameInput}";

                // --- Loop through certificates ---
                foreach (X509Certificate2 cert in store.Certificates)
                {
                    using (cert)
                    {
                        // Calculate daysLeft (scoped inside loop)
                        TimeSpan remainingTime = cert.NotAfter.ToUniversalTime() - nowUtc;
                        int daysLeft = (int)Math.Ceiling(remainingTime.TotalDays); // Declared and assigned

                        // Apply Regex Filter (if any)
                        if (filterRegex != null)
                        {
                            bool subjectMatch = !string.IsNullOrEmpty(cert.SubjectName.Name) && filterRegex.IsMatch(cert.SubjectName.Name);
                            bool friendlyNameMatch = !string.IsNullOrEmpty(cert.FriendlyName) && filterRegex.IsMatch(cert.FriendlyName);
                            if (!subjectMatch && !friendlyNameMatch) { continue; } // Skip if no match
                        }

                        // Create CertificateInfo (scoped inside loop)
                        var certInfo = new CertificateInfo
                        {
                            Subject = cert.SubjectName.Name ?? "(No Subject)",
                            FriendlyName = cert.FriendlyName ?? "(No Friendly Name)",
                            ExpiryDate = cert.NotAfter,
                            DaysLeft = daysLeft, // Use calculated daysLeft
                            Thumbprint = cert.Thumbprint ?? "(No Thumbprint)",
                            StoreLocationName = storeLocation.ToString(),
                            StoreNameInput = storeNameInput,
                            StorePath = storePathBase
                        };

                        // Check for Email list
                        if (emailNotify && certInfo.DaysLeft > 0 && certInfo.DaysLeft <= emailCheckThresholdDays)
                        {
                            certificatesExpiringSoonForEmail.Add(certInfo);
                        }

                        // Apply Date Filters for Console Output
                        bool displayThisCert = true; // Declare displayThisCert inside loop scope
                        if (expireWithinDaysFilter.HasValue)
                        {
                            if (!(certInfo.DaysLeft > 0 && certInfo.DaysLeft <= expireWithinDaysFilter.Value))
                            {
                                displayThisCert = false;
                            }
                        }
                        else if (showExpiredOnly)
                        {
                            if (certInfo.DaysLeft > 0)
                            { // Only show if <= 0
                                displayThisCert = false;
                            }
                        }

                        // Add to display list if applicable
                        if (displayThisCert)
                        { // Use displayThisCert correctly scoped
                            certificatesToDisplay.Add(certInfo);
                        }
                    } // cert disposed here
                } // End foreach loop

                // --- Display Results ---
                if (certificatesToDisplay.Any())
                {
                    Console.WriteLine(GetFormattedHeader()); // Call helper
                    Console.WriteLine(new string('-', TotalConsoleWidth));
                    foreach (var certInfo in certificatesToDisplay.OrderBy(c => c.ExpiryDate))
                    {
                        Console.WriteLine(FormatCertificateInfo(certInfo)); // Call helper
                    }
                    Console.WriteLine(new string('-', TotalConsoleWidth));
                }
                else { Console.WriteLine("No certificates match the specified filters for display."); }

                Console.WriteLine($"Processed {store.Certificates.Count} total certificates. Displayed {certificatesToDisplay.Count}.");

                // --- Send Email ---
                if (emailNotify && certificatesExpiringSoonForEmail.Any())
                {
                    Console.WriteLine($"\nFound {certificatesExpiringSoonForEmail.Count} certificate(s) expiring within {emailCheckThresholdDays} days. Attempting email notification...");
                    bool emailSent = SendExpiryEmail(certificatesExpiringSoonForEmail, emailConfig, emailCheckThresholdDays);
                    if (emailSent) { Console.WriteLine("Email notification sent successfully."); }
                    else { Console.Error.WriteLine("Failed to send email notification. Check logs and config."); }
                }
                else if (emailNotify) { Console.WriteLine($"\nNo certificates found expiring within the notification threshold ({emailCheckThresholdDays} days). No email sent."); }

                if (storeLocation == StoreLocation.LocalMachine) { Console.WriteLine("\nNote: Accessing/Modifying the LocalMachine store typically requires Administrator privileges."); }
                return 0; // Success

            }
            catch (SecurityException ex)
            {
                Console.Error.WriteLine($"\nERROR: Permission denied accessing store '{storeLocation}/{storeNameInput}'. Run as Admin?");
                Console.Error.WriteLine($"       Details: {ex.Message}"); return 2;
            }
            catch (CryptographicException ex)
            {
                Console.Error.WriteLine($"\nERROR: Cryptographic error accessing store '{storeLocation}/{storeNameInput}'. Store exists? Permissions?");
                Console.Error.WriteLine($"       Details: {ex.Message}"); return 3;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"\nAn unexpected error occurred during listing: {ex.GetType().Name}");
                Console.Error.WriteLine($"       Message: {ex.Message}");
                Console.Error.WriteLine($"       Stack Trace: {ex.StackTrace}"); return 99;
            }
            finally
            {
                store?.Close(); Console.WriteLine("--> DEBUG: Store closed.");
            }
        } // End ListAndNotifyCertificates

        // --- Helper: Format Header ---
        static string GetFormattedHeader() // Ensures return value
        {
            string headerFormat = "{0,-" + SubjectWidth + "} | {1,-" + FriendlyNameWidth + "} | {2,-" + ExpiresOnWidth + "} | {3,-" + DaysLeftWidth + "} | {4,-" + ThumbprintWidth + "} | {5}";
            return string.Format(headerFormat,
                "Subject",          // {0}
                "Friendly Name",    // {1}
                "Expires On",       // {2}
                "Days Left",        // {3}
                "Thumbprint",       // {4}
                "PS Remove Cmd");   // {5} - 6 arguments
        }

        // --- Helper: Format Certificate Line ---
        static string FormatCertificateInfo(CertificateInfo certInfo) // Ensures correct arguments for format
        {
            string displaySubject = certInfo.Subject.Length > SubjectWidth - 2 ? certInfo.Subject.Substring(0, SubjectWidth - 5) + "..." : certInfo.Subject;
            string displayFriendlyName = certInfo.FriendlyName.Length > FriendlyNameWidth - 2 ? certInfo.FriendlyName.Substring(0, FriendlyNameWidth - 5) + "..." : certInfo.FriendlyName;
            string psRemoveCommand = $"Remove-Item -Path \"{certInfo.StorePath}\\{certInfo.Thumbprint}\"";
            string lineFormat = "{0,-" + SubjectWidth + "} | {1,-" + FriendlyNameWidth + "} | {2,-" + ExpiresOnWidth + ":yyyy-MM-dd} | {3,-" + DaysLeftWidth + "} | {4,-" + ThumbprintWidth + "} | {5}";
            return string.Format(lineFormat,
                displaySubject,              // {0}
                displayFriendlyName,       // {1}
                certInfo.ExpiryDate,       // {2}
                certInfo.DaysLeft,         // {3}
                certInfo.Thumbprint,         // {4}
                psRemoveCommand);          // {5} - 6 arguments
        }

        // --- Deletion Mode ---
        static int HandleDeletion(StoreLocation storeLocation, string storeNameInput, string thumbprintToDelete, bool force)
        {
            Console.WriteLine($"\nAttempting to delete certificate with Thumbprint: {thumbprintToDelete}");
            Console.WriteLine($"From Store: {storeLocation}/{storeNameInput}");
            if (storeLocation == StoreLocation.LocalMachine) { Console.WriteLine("\nWARNING: Deleting from LocalMachine store requires Administrator privileges!"); }
            Console.WriteLine("WARNING: This action is irreversible (though a backup will be attempted).");

            X509Store store = null;
            X509Certificate2 certToDelete = null;
            X509Certificate2Collection foundCertificates = null; // Declare higher for finally block access

            try
            {
                store = new X509Store(storeNameInput, storeLocation);
                store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
                Console.WriteLine("--> DEBUG: Store opened with ReadWrite access.");

                foundCertificates = store.Certificates.Find( // Assign to scoped variable
                    X509FindType.FindByThumbprint, thumbprintToDelete, false);

                if (foundCertificates.Count == 0)
                {
                    Console.Error.WriteLine($"\nERROR: Certificate with Thumbprint '{thumbprintToDelete}' not found in {storeLocation}/{storeNameInput}."); return 10;
                }
                else if (foundCertificates.Count > 1)
                {
                    Console.Error.WriteLine($"\nERROR: Multiple certificates found with Thumbprint '{thumbprintToDelete}'. Aborting.");
                    // Dispose directly here since we are aborting
                    foreach (X509Certificate2 cert in foundCertificates) { cert.Dispose(); }
                    return 11;
                }

                certToDelete = foundCertificates[0]; // Assign the single cert

                Console.WriteLine("\nCertificate Found:");
                Console.WriteLine($"  Subject:      {certToDelete.Subject}");
                Console.WriteLine($"  Issuer:       {certToDelete.Issuer}");
                Console.WriteLine($"  Thumbprint:   {certToDelete.Thumbprint}");
                Console.WriteLine($"  Serial No:    {certToDelete.SerialNumber}");
                Console.WriteLine($"  Expires:      {certToDelete.NotAfter:yyyy-MM-dd HH:mm:ss}");
                Console.WriteLine($"  FriendlyName: {certToDelete.FriendlyName ?? "(None)"}");

                if (!force)
                {
                    Console.Write("\nARE YOU SURE you want to permanently delete this certificate? (A backup .cer file will be created first) [y/N]: ");
                    string confirmation = Console.ReadLine();
                    if (!confirmation.Trim().Equals("Y", StringComparison.OrdinalIgnoreCase))
                    {
                        Console.WriteLine("Deletion cancelled by user."); return 0;
                    }
                }
                else { Console.WriteLine("\nProceeding with deletion due to --yes flag."); }

                // --- Export Backup ---
                string safeThumbprint = Regex.Replace(thumbprintToDelete, "[^0-9a-zA-Z]", "");
                string backupFileName = $"{safeThumbprint}_{storeLocation}_{storeNameInput}.cer";

                string backupFilePath = Path.Combine(Directory.GetCurrentDirectory(), backupFileName); // CORRECT


                Console.WriteLine($"Attempting to export backup to: {backupFilePath}");
                if (!ExportCertificate(certToDelete, backupFilePath))
                {
                    Console.Error.WriteLine($"\nERROR: Failed to export certificate backup to '{backupFilePath}'.");
                    if (!force)
                    {
                        Console.Write("Do you still want to proceed with deletion? This is risky without a backup. [y/N]: ");
                        string proceedAnyway = Console.ReadLine();
                        if (!proceedAnyway.Trim().Equals("Y", StringComparison.OrdinalIgnoreCase))
                        {
                            Console.WriteLine("Deletion cancelled due to export failure."); return 12;
                        }
                        Console.WriteLine("Proceeding with deletion despite export failure as requested by user.");
                    }
                    else { Console.WriteLine("Proceeding with deletion despite export failure due to --yes flag."); }
                }
                else { Console.WriteLine("Backup exported successfully."); }

                // --- Delete Certificate ---
                Console.WriteLine("Attempting to remove certificate from the store...");
                store.Remove(certToDelete);
                Console.WriteLine("Certificate successfully removed from the store.");
                return 0; // Success

            }
            catch (SecurityException ex)
            {
                Console.Error.WriteLine($"\nERROR: Permission denied during deletion from '{storeLocation}/{storeNameInput}'. Run as Admin?");
                Console.Error.WriteLine($"       Details: {ex.Message}"); return 2;
            }
            catch (CryptographicException ex)
            {
                Console.Error.WriteLine($"\nERROR: Cryptographic error during deletion from '{storeLocation}/{storeNameInput}'. Store exists? Permissions?");
                if (ex.Message.Contains("Keyset does not exist")) { Console.Error.WriteLine("       Hint: Keyset error often means permission issue even for deletion."); }
                Console.Error.WriteLine($"       Details: {ex.Message}"); return 3;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"\nAn unexpected error occurred during deletion: {ex.GetType().Name}");
                Console.Error.WriteLine($"       Message: {ex.Message}");
                Console.Error.WriteLine($"       Stack Trace: {ex.StackTrace}"); return 99;
            }
            finally
            {
                // Dispose the single certificate object if it was assigned
                certToDelete?.Dispose();

                // Dispose other certs in the collection (if it was assigned and had items)
                // to prevent resource leaks if something went wrong after Find but before Remove
                if (foundCertificates != null)
                {
                    foreach (X509Certificate2 cert in foundCertificates)
                    {
                        // Avoid disposing the certToDelete object twice
                        if (cert != certToDelete)
                        {
                            cert.Dispose();
                        }
                    }
                }
                store?.Close();
                Console.WriteLine("--> DEBUG: Store closed after deletion attempt.");
            }
        } // End HandleDeletion


        // --- Helper: Export Certificate ---
        static bool ExportCertificate(X509Certificate2 cert, string filePath)
        {
            try
            {
                byte[] certData = cert.Export(X509ContentType.Cert);
                if (certData == null || certData.Length == 0) { Console.Error.WriteLine("  -> Export Error: Export method returned null or empty data."); return false; }
                File.WriteAllBytes(filePath, certData);
                return true;
            }
            catch (IOException ex) { Console.Error.WriteLine($"  -> Export I/O Error writing to '{filePath}': {ex.Message}"); return false; }
            catch (SecurityException ex) { Console.Error.WriteLine($"  -> Export Security Error writing to '{filePath}': {ex.Message}"); return false; }
            catch (CryptographicException ex) { Console.Error.WriteLine($"  -> Export Crypto Error: {ex.Message}"); return false; }
            catch (Exception ex) { Console.Error.WriteLine($"  -> Unexpected Export Error: {ex.GetType().Name} - {ex.Message}"); return false; }
        }

        #region Email Notification Logic

        // --- Helper: Read Email Configuration ---
        static EmailConfig ReadEmailConfiguration(ref int defaultNotifyDays)
        {
            var config = new EmailConfig();
            bool configError = false;

            try
            {
                var appSettings = ConfigurationManager.AppSettings;

                Func<string, string, string> readRequiredSetting = (key, description) => {
                    string value = appSettings[key];
                    if (string.IsNullOrWhiteSpace(value)) { LogConfigError($"Required setting '{key}' ({description}) missing or empty."); configError = true; return null; }
                    return value.Trim();
                };
                Func<string, string> readOptionalSetting = (key) => {
                    string value = appSettings[key]; return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
                };

                config.SmtpServer = readRequiredSetting("SmtpServer", "SMTP Server Address");
                string portStr = readRequiredSetting("SmtpPort", "SMTP Port");
                if (portStr != null) { if (int.TryParse(portStr, out int parsedPort) && parsedPort > 0) { config.SmtpPort = parsedPort; } else { LogConfigError("'SmtpPort' is not a valid positive integer."); configError = true; } }
                string sslStr = readRequiredSetting("SmtpEnableSsl", "Enable SSL/TLS");
                if (sslStr != null) { if (bool.TryParse(sslStr, out bool parsedSsl)) { config.EnableSsl = parsedSsl; } else { LogConfigError("'SmtpEnableSsl' is not a valid boolean (true/false)."); configError = true; } }
                string userBase64 = readOptionalSetting("SmtpUsernameBase64");
                string passBase64 = readOptionalSetting("SmtpPasswordBase64");
                if (userBase64 != null) { try { config.Username = Encoding.UTF8.GetString(Convert.FromBase64String(userBase64)); } catch (FormatException) { LogConfigError("'SmtpUsernameBase64' is not valid Base64."); configError = true; } }
                if (passBase64 != null) { try { config.Password = Encoding.UTF8.GetString(Convert.FromBase64String(passBase64)); } catch (FormatException) { LogConfigError("'SmtpPasswordBase64' is not valid Base64."); configError = true; } }
                if (!string.IsNullOrWhiteSpace(config.Username) && passBase64 == null) { Console.WriteLine($"Warning [Config File]: 'SmtpUsernameBase64' provided, but 'SmtpPasswordBase64' missing."); }
                config.FromAddress = readRequiredSetting("MailFromAddress", "Sender Email Address");
                if (config.FromAddress != null && !config.FromAddress.Contains("@")) { LogConfigError("'MailFromAddress' does not appear valid."); configError = true; }
                string recipientsStr = readRequiredSetting("MailToRecipients", "Recipient Email Addresses");
                if (recipientsStr != null) { config.ToRecipients.AddRange(recipientsStr.Split(';').Select(r => r.Trim()).Where(r => !string.IsNullOrWhiteSpace(r) && r.Contains('@'))); if (!config.ToRecipients.Any()) { LogConfigError("'MailToRecipients' contains no valid addresses."); configError = true; } }
                string defaultDaysStr = readOptionalSetting("ExpireNotifyDaysDefault");
                if (defaultDaysStr != null) { if (int.TryParse(defaultDaysStr, out int parsedDays) && parsedDays > 0) { defaultNotifyDays = parsedDays; Console.WriteLine($"--> DEBUG: Using ExpireNotifyDaysDefault from config: {defaultNotifyDays}"); } else { Console.Error.WriteLine($"Warning [Config File]: 'ExpireNotifyDaysDefault' invalid. Using default ({defaultNotifyDays})."); } } else { Console.WriteLine($"--> DEBUG: Using default ExpireNotifyDaysDefault: {defaultNotifyDays}"); }
            }
            catch (ConfigurationErrorsException ex) { LogConfigError($"Error reading configuration section: {ex.Message}"); configError = true; }
            catch (Exception ex) { LogConfigError($"Unexpected error reading configuration: {ex.Message}"); configError = true; }

            return configError ? null : config;
        }

        // --- Helper: Log Configuration Errors ---
        static void LogConfigError(string message, string source = null)
        {
            if (source == null) { try { var configFile = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None); source = Path.GetFileName(configFile.FilePath); } catch { source = "Config File"; } }
            Console.Error.WriteLine($"ERROR [{source}]: {message}");
        }

        // --- Helper: Send Email Notification ---
        static bool SendExpiryEmail(List<CertificateInfo> expiringCerts, EmailConfig config, int thresholdDays)
        {
            if (config == null) { Console.Error.WriteLine("Cannot send email: Email configuration invalid."); return false; }
            if (!expiringCerts.Any()) { Console.WriteLine("No expiring certificates found for email."); return true; }
            Console.WriteLine($"--> DEBUG: Attempting email via {config.SmtpServer}:{config.SmtpPort} SSL={config.EnableSsl}");
            try
            {
                using (var smtpClient = new SmtpClient(config.SmtpServer, config.SmtpPort))
                {
                    smtpClient.EnableSsl = config.EnableSsl;
                    if (!string.IsNullOrWhiteSpace(config.Username)) { smtpClient.UseDefaultCredentials = false; smtpClient.Credentials = new NetworkCredential(config.Username, config.Password); Console.WriteLine("--> DEBUG: Using provided SMTP credentials."); }
                    else { smtpClient.UseDefaultCredentials = true; Console.WriteLine("--> DEBUG: Using default/anonymous SMTP credentials."); }
                    smtpClient.Timeout = 30000; // 30 second timeout

                    using (var mailMessage = new MailMessage())
                    {
                        mailMessage.From = new MailAddress(config.FromAddress);
                        foreach (var recipient in config.ToRecipients) { if (!string.IsNullOrWhiteSpace(recipient) && recipient.Contains("@")) { mailMessage.To.Add(recipient); } else { Console.WriteLine($"Warning: Skipping invalid recipient: '{recipient}'"); } }
                        if (mailMessage.To.Count == 0) { Console.Error.WriteLine("Cannot send email: No valid recipients."); return false; }

                        mailMessage.Subject = $"Certificate Expiry Warning ({expiringCerts.Count} expiring soon on {Environment.MachineName})";
                        mailMessage.IsBodyHtml = true;
                        var bodyBuilder = new StringBuilder();
                        bodyBuilder.Append("<html><head><style>table, th, td { border: 1px solid black; border-collapse: collapse; padding: 5px; font-family: sans-serif; font-size: 9pt; } th { background-color: #f2f2f2; text-align: left; } td.num { text-align: right; }</style></head><body>");
                        bodyBuilder.Append($"<h2>Certificate Expiry Notification</h2>");
                        bodyBuilder.Append($"<p>The following certificate(s) found on <b>{WebUtility.HtmlEncode(Environment.MachineName)}</b> are expiring within <b>{thresholdDays} days</b> or less:</p>");
                        bodyBuilder.Append("<table>");
                        bodyBuilder.Append("<tr><th>Subject</th><th>Friendly Name</th><th>Store</th><th>Expires On</th><th>Days Left</th><th>Thumbprint</th></tr>");
                        foreach (var cert in expiringCerts.OrderBy(c => c.ExpiryDate))
                        {
                            bodyBuilder.AppendFormat("<tr><td>{0}</td><td>{1}</td><td>{2}/{3}</td><td>{4:yyyy-MM-dd}</td><td class='num'>{5}</td><td>{6}</td></tr>",
                                WebUtility.HtmlEncode(cert.Subject), WebUtility.HtmlEncode(cert.FriendlyName), WebUtility.HtmlEncode(cert.StoreLocationName), WebUtility.HtmlEncode(cert.StoreNameInput),
                                cert.ExpiryDate, cert.DaysLeft, cert.Thumbprint);
                        }
                        bodyBuilder.Append("</table>");
                        bodyBuilder.Append("<p style='margin-top: 15px;'>Please take appropriate action to renew or replace these certificates.</p>");
                        bodyBuilder.Append($"<p><small>Report generated by CertificateChecker tool on: {DateTime.Now:yyyy-MM-dd HH:mm:ss}</small></p>");
                        bodyBuilder.Append("</body></html>");
                        mailMessage.Body = bodyBuilder.ToString();

                        Console.WriteLine($"--> DEBUG: Sending email to {string.Join("; ", mailMessage.To.Select(a => a.Address))}...");
                        smtpClient.Send(mailMessage);
                        Console.WriteLine("--> DEBUG: SmtpClient.Send completed.");
                        return true;
                    }
                }
            }
            catch (SmtpException ex) { Console.Error.WriteLine($"\nSMTP Error: {ex.StatusCode}. {ex.Message}"); if (ex.InnerException != null) Console.Error.WriteLine($"  Inner: {ex.InnerException.Message}"); return false; }
            catch (InvalidOperationException ex) { Console.Error.WriteLine($"\nMail Error: {ex.Message}"); return false; }
            catch (FormatException ex) { Console.Error.WriteLine($"\nMail Address Error: Check From/To addresses. {ex.Message}"); return false; }
            catch (Exception ex) { Console.Error.WriteLine($"\nUnexpected Error sending email: {ex.GetType().Name} - {ex.Message}\n{ex.StackTrace}"); return false; }
        }

        #endregion // Email Notification Logic

        // --- Help Text ---
        static void PrintUsage()
        {
            Console.WriteLine("\nCertificate Expiry Checker and Manager (v2.2)");
            Console.WriteLine("Checks certificates, filters by expiry/regex, suggests removal commands, optionally deletes, and sends email alerts.");
            Console.WriteLine("\nUsage: CertificateChecker.exe [options]");
            Console.WriteLine("       CertificateChecker.exe --delete <Thumbprint> [options]");
            Console.WriteLine("\nGeneral Options:");
            Console.WriteLine("  -sl, --store-location <Location>   Specify the store location.");
            Console.WriteLine($"                                     (Default: LocalMachine). Valid: {string.Join(", ", Enum.GetNames(typeof(StoreLocation)))}");
            Console.WriteLine("  -sn, --store-name <Name>           Specify the name of the certificate store.");
            Console.WriteLine("                                     (Default: My). Examples: My, Root, CA, RemoteDesktop, WebHosting");
            Console.WriteLine("  -f,  --filter <RegexPattern>       Filter by Subject/Friendly Name (case-insensitive RegEx).");
            Console.WriteLine("  -h,  --help                        Displays this help message.");
            Console.WriteLine("\nDate Filtering Options (ignored if --delete is used):");
            Console.WriteLine("  -ew, --expire-within <Days>        Show certs expiring in <Days> or less (excludes already expired).");
            Console.WriteLine("       --expired                     Show only certificates that have already expired (Days Left <= 0).");
            Console.WriteLine("       (Cannot use --expire-within and --expired together)");
            Console.WriteLine("\nEmail Notification Option (ignored if --delete is used):");
            Console.WriteLine("  -en, --email-notify               Send an email if certificates are found expiring soon.");
            Console.WriteLine("                                     Uses settings from App.config. Email includes certs expiring");
            Console.WriteLine("                                     within <Days> from --expire-within OR ExpireNotifyDaysDefault");
            Console.WriteLine("                                     from App.config if --expire-within is not used.");
            Console.WriteLine("\nDeletion Options (overrides filtering/notification):");
            Console.WriteLine("  -d,  --delete <Thumbprint>         Specifies the thumbprint of the certificate to delete.");
            Console.WriteLine("                                     Thumbprint can include spaces, they will be removed.");
            Console.WriteLine("                                     Requires Administrator privileges if deleting from LocalMachine.");
            Console.WriteLine("  -y,  --yes                         Suppress the confirmation prompt before deleting (USE WITH CAUTION!).");
            Console.WriteLine("\nExamples:");
            Console.WriteLine("  CertificateChecker.exe");
            Console.WriteLine("      List certs in LocalMachine/My.");
            Console.WriteLine("  CertificateChecker.exe -sn Root");
            Console.WriteLine("      List certs in LocalMachine/Root (Requires Admin).");
            Console.WriteLine("  CertificateChecker.exe -sn RemoteDesktop -sl LocalMachine");
            Console.WriteLine("      List certs in LocalMachine/RemoteDesktop (Requires Admin).");
            Console.WriteLine("  CertificateChecker.exe -ew 30 -sn WebHosting");
            Console.WriteLine("      List certs in LocalMachine/WebHosting expiring in 30 days or less (Requires Admin).");
            Console.WriteLine("  CertificateChecker.exe --expired -sl CurrentUser");
            Console.WriteLine("      List expired certs in CurrentUser/My.");
            Console.WriteLine("  CertificateChecker.exe -ew 60 -en -f \"corp.com\"");
            Console.WriteLine("      List certs matching 'corp.com' expiring in 60 days or less, and email if any are found.");
            Console.WriteLine("  CertificateChecker.exe -en");
            Console.WriteLine("      List all certs (default store), and email if any expire within the default config threshold.");
            Console.WriteLine("  CertificateChecker.exe -d \"11 22 33 ... FF 00\" -y");
            Console.WriteLine("      Delete cert with specified thumbprint from LocalMachine/My without prompt (Requires Admin).");
            Console.WriteLine("\nConfiguration: Email settings are managed in CertificateChecker.exe.config");
            Console.WriteLine("WARNING: Deleting certificates is irreversible. Always verify the thumbprint.");
            Console.WriteLine("         Accessing/Deleting from LocalMachine store requires Administrator privileges.");
        } // End PrintUsage

    } // End Class Program
} // End Namespace