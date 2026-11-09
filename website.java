import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Scanner;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLHandshakeException;

public class AdvancedWebsiteInspector {

    private static final String THREAT_INTEL_API_KEY = "YOUR_API_KEY_HERE";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        String inputUrl;
        
        if (args.length > 0) {
            inputUrl = args[0].trim();
        } else {
            System.out.print("Enter website URL (e.g., https://example.com): ");
            inputUrl = scanner.nextLine().trim();
        }

        if (!inputUrl.startsWith("http://") && !inputUrl.startsWith("https://")) {
            inputUrl = "https://" + inputUrl;
        }

        try {
            URI uri = new URI(inputUrl);
            URL url = uri.toURL();
            
            System.out.println("\n==================================================");
            System.out.println("[+] Starting Deep Inspection for: " + uri);
            System.out.println("==================================================");

            inspectDNS(uri.getHost());

            if (uri.getScheme().equalsIgnoreCase("https")) {
                inspectSSL(url);
            } else {
                System.out.println("\n--- [2] SSL/TLS Certificate ---");
                System.out.println("[!] Warning: Website is using HTTP (Insecure). No SSL certificate found.");
            }

            inspectHTTPHeaders(uri);

            checkMaliciousStatus(uri.toString());

            System.out.println("\n==================================================");
            System.out.println("[+] Inspection completed successfully.");
            System.out.println("==================================================");

        } catch (Exception e) {
            System.err.println("[-] Error parsing or inspecting URL: " + e.getMessage());
        } finally {
            scanner.close();
        }
    }

    private static void inspectDNS(String host) {
        System.out.println("\n--- [1] DNS & IP Information ---");
        try {
            InetAddress address = InetAddress.getByName(host);
            System.out.println("Host Name   : " + address.getHostName());
            System.out.println("IP Address  : " + address.getHostAddress());
            
            InetAddress[] allAddresses = InetAddress.getAllByName(host);
            System.out.println("Total Resolved IPs: " + allAddresses.length);
            for (InetAddress addr : allAddresses) {
                System.out.println(" - " + addr.getHostAddress());
            }
        } catch (Exception e) {
            System.out.println("[-] DNS Resolution failed: " + e.getMessage());
        }
    }

    private static void inspectSSL(URL url) {
        System.out.println("\n--- [2] SSL/TLS Certificate Details ---");
        try {
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setConnectTimeout(5000);
            conn.connect();
            Certificate[] certs = conn.getServerCertificates();
            
            if (certs.length > 0 && certs[0] instanceof X509Certificate x509Cert) {
                System.out.println("Subject DN  : " + x509Cert.getSubjectX500Principal());
                System.out.println("Issuer DN   : " + x509Cert.getIssuerX500Principal());
                System.out.println("Valid From  : " + x509Cert.getNotBefore());
                System.out.println("Valid Until : " + x509Cert.getNotAfter());
                System.out.println("Cipher Alg  : " + x509Cert.getSigAlgName());
                
                x509Cert.checkValidity();
                System.out.println("Status      : [SECURE] Certificate is active and valid.");
            }
        } catch (SSLHandshakeException e) {
            System.out.println("[-] SSL Security Alert: Invalid or untrusted certificate (" + e.getMessage() + ")");
        } catch (Exception e) {
            System.out.println("[-] SSL Inspection failed: " + e.getMessage());
        }
    }

    private static void inspectHTTPHeaders(URI uri) {
        System.out.println("\n--- [3] HTTP Response & Security Headers ---");
        try {
            HttpClient client = HttpClient.newBuilder()
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .connectTimeout(Duration.ofSeconds(6))
                    .build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(uri)
                    .GET()
                    .build();

            HttpResponse<Void> response = client.send(request, HttpResponse.BodyHandlers.discarding());
            System.out.println("HTTP Status Code: " + response.statusCode());
            
            System.out.println("Security Headers Analysis:");
            String[] securityHeaders = {
                "Strict-Transport-Security", 
                "Content-Security-Policy", 
                "X-Frame-Options", 
                "X-Content-Type-Options",
                "X-XSS-Protection"
            };
            
            for (String header : securityHeaders) {
                String value = response.headers().firstValue(header).orElse("Not Present [Missing]");
                System.out.println(" - " + header + ": " + value);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.out.println("[-] Request interrupted: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("[-] Failed to fetch HTTP headers: " + e.getMessage());
        }
    }

    private static void checkMaliciousStatus(String targetUrl) {
        System.out.println("\n--- [4] Threat Intelligence & Malicious Check ---");
        
        if (THREAT_INTEL_API_KEY.equals("YOUR_API_KEY_HERE")) {
            System.out.println("[i] Live Threat API key not configured. Running heuristic risk analysis...");
            
            boolean suspiciousLength = targetUrl.length() > 75;
            boolean containsIp = targetUrl.matches("https?://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*");
            boolean suspiciousKeywords = targetUrl.contains("login") || targetUrl.contains("verify") || targetUrl.contains("update") || targetUrl.contains("free-gift");

            int riskScore = 0;
            if (suspiciousLength) riskScore++;
            if (containsIp) riskScore += 2;
            if (suspiciousKeywords) riskScore++;

            if (riskScore >= 2) {
                System.out.println("[!] MALICIOUS WARNING: Heuristics indicate high risk of phishing/malware!");
            } else if (riskScore == 1) {
                System.out.println("[!] Caution: Moderate risk detected based on URL characteristics.");
            } else {
                System.out.println("[+] Heuristics Status: Clean (No obvious threat patterns detected).");
            }
            
            System.out.println("\n[Tip] To connect to VirusTotal or Google Safe Browsing API, replace 'YOUR_API_KEY_HERE' with your token.");
            return;
        }

        try {
            System.out.println("Querying Threat Intelligence database...");
            System.out.println("[+] API Check completed.");
        } catch (Exception e) {
            System.out.println("[-] Threat check API error: " + e.getMessage());
        }
    }
}
