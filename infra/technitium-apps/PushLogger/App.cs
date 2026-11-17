using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using DnsServerCore.ApplicationCommon;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace PushLogger
{
    // Real-time push alternative to polling data/raw/*.log: Technitium calls InsertLogAsync
    // itself, synchronously in the query-answering path, right after each query is answered.
    // InsertLogAsync must never block or throw - it only enqueues; a background task does the
    // actual HTTP POST so a slow/unreachable listener can never delay DNS resolution.
    public sealed class App : IDnsApplication, IDnsQueryLogger
    {
        HttpClient _httpClient;
        Channel<LogEntry> _channel;
        CancellationTokenSource _cts;
        Task _workerTask;
        string _pushUrl;
        string _pushToken;

        public string Description => "Pushes each DNS query log in real time via HTTP POST to scripts/technitium_push_listener.py (no polling).";

        public Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            StopWorker();

            string pushUrl = "http://172.20.0.1:8787/push";
            string pushToken = "";
            int maxQueueSize = 10000;
            int timeoutMs = 2000;

            if (!string.IsNullOrEmpty(config))
            {
                using (JsonDocument doc = JsonDocument.Parse(config))
                {
                    JsonElement root = doc.RootElement;
                    if (root.TryGetProperty("pushUrl", out JsonElement v1))
                        pushUrl = v1.GetString();
                    if (root.TryGetProperty("pushToken", out JsonElement v2))
                        pushToken = v2.GetString();
                    if (root.TryGetProperty("maxQueueSize", out JsonElement v3))
                        maxQueueSize = v3.GetInt32();
                    if (root.TryGetProperty("timeoutMs", out JsonElement v4))
                        timeoutMs = v4.GetInt32();
                }
            }

            _pushUrl = pushUrl;
            _pushToken = pushToken ?? "";

            _httpClient = new HttpClient();
            _httpClient.Timeout = TimeSpan.FromMilliseconds(timeoutMs);

            BoundedChannelOptions options = new BoundedChannelOptions(maxQueueSize)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = true,
                SingleWriter = false
            };
            _channel = Channel.CreateBounded<LogEntry>(options);
            _cts = new CancellationTokenSource();
            _workerTask = Task.Run(() => WorkerLoopAsync(_channel, _cts.Token));

            return Task.CompletedTask;
        }

        public Task InsertLogAsync(DateTime timestamp, DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
        {
            try
            {
                LogEntry entry = LogEntry.From(timestamp, request, remoteEP, protocol, response);
                Channel<LogEntry> channel = _channel;
                if (channel != null)
                    channel.Writer.TryWrite(entry);
            }
            catch
            {
                // Never let a logging failure affect the DNS response path.
            }

            return Task.CompletedTask;
        }

        async Task WorkerLoopAsync(Channel<LogEntry> channel, CancellationToken cancellationToken)
        {
            HttpClient httpClient = _httpClient;
            string pushUrl = _pushUrl;
            string pushToken = _pushToken;

            try
            {
                while (await channel.Reader.WaitToReadAsync(cancellationToken))
                {
                    while (channel.Reader.TryRead(out LogEntry entry))
                    {
                        try
                        {
                            string json = entry.ToJson(pushToken);
                            using (StringContent content = new StringContent(json, Encoding.UTF8, "application/json"))
                            using (HttpResponseMessage resp = await httpClient.PostAsync(pushUrl, content, cancellationToken))
                            {
                                // Best-effort delivery: no retry, so a slow/unreachable listener
                                // never builds an unbounded backlog here.
                            }
                        }
                        catch (OperationCanceledException)
                        {
                            throw;
                        }
                        catch
                        {
                            // Listener unreachable/slow - drop this entry and keep going.
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
            }
        }

        void StopWorker()
        {
            try { _cts?.Cancel(); } catch { }
            try { _channel?.Writer.TryComplete(); } catch { }
            try { _httpClient?.Dispose(); } catch { }
        }

        public void Dispose()
        {
            StopWorker();
        }
    }

    internal readonly struct LogEntry
    {
        public readonly DateTime Timestamp;
        public readonly string ClientIp;
        public readonly int ClientPort;
        public readonly string Protocol;
        public readonly string QName;
        public readonly string QType;
        public readonly string QClass;
        public readonly string RCode;
        public readonly List<string> Answers;

        LogEntry(DateTime timestamp, string clientIp, int clientPort, string protocol, string qname, string qtype, string qclass, string rcode, List<string> answers)
        {
            Timestamp = timestamp;
            ClientIp = clientIp;
            ClientPort = clientPort;
            Protocol = protocol;
            QName = qname;
            QType = qtype;
            QClass = qclass;
            RCode = rcode;
            Answers = answers;
        }

        public static LogEntry From(DateTime timestamp, DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
        {
            string qname = "";
            string qtype = "unknown";
            string qclass = "IN";

            if ((request != null) && (request.Question.Count > 0))
            {
                DnsQuestionRecord q = request.Question[0];
                qname = q.Name;
                qtype = q.Type.ToString();
                qclass = q.Class.ToString();
            }

            string rcode = response != null ? response.RCODE.ToString() : "unknown";

            List<string> answers = new List<string>();
            if ((response != null) && (response.Answer != null))
            {
                foreach (DnsResourceRecord rr in response.Answer)
                    answers.Add(FormatRData(rr));
            }

            string ip = remoteEP != null ? remoteEP.Address.ToString() : "unknown";
            int port = remoteEP != null ? remoteEP.Port : 0;

            // Technitium's own log files label this "Local" (server-local time), not UTC - the
            // extractor's regex requires that exact word, so keep the timestamp as given.
            return new LogEntry(timestamp, ip, port, ProtocolToString(protocol), qname, qtype, qclass, rcode, answers);
        }

        static string ProtocolToString(DnsTransportProtocol protocol)
        {
            switch (protocol)
            {
                case DnsTransportProtocol.Udp: return "UDP";
                case DnsTransportProtocol.Tcp: return "TCP";
                case DnsTransportProtocol.Tls: return "TLS";
                case DnsTransportProtocol.Https: return "HTTPS";
                case DnsTransportProtocol.HttpsJson: return "HTTPSJSON";
                case DnsTransportProtocol.Quic: return "QUIC";
                default: return protocol.ToString().ToUpperInvariant();
            }
        }

        static string FormatRData(DnsResourceRecord rr)
        {
            try
            {
                switch (rr.RDATA)
                {
                    case DnsARecordData a: return a.Address.ToString();
                    case DnsAAAARecordData aaaa: return aaaa.Address.ToString();
                    case DnsCNAMERecordData cname: return cname.Domain;
                    case DnsNSRecordData ns: return ns.NameServer;
                    case DnsPTRRecordData ptr: return ptr.Domain;
                    case DnsMXRecordData mx: return mx.Exchange;
                    case DnsTXTRecordData txt: return txt.GetText();
                    default: return rr.Type.ToString();
                }
            }
            catch
            {
                return rr.Type.ToString();
            }
        }

        public string ToJson(string pushToken)
        {
            using (System.IO.MemoryStream ms = new System.IO.MemoryStream())
            {
                using (Utf8JsonWriter writer = new Utf8JsonWriter(ms))
                {
                    writer.WriteStartObject();
                    writer.WriteString("token", pushToken ?? "");
                    writer.WriteString("timestamp", Timestamp.ToString("yyyy-MM-dd HH:mm:ss"));
                    writer.WriteString("clientIp", ClientIp);
                    writer.WriteNumber("clientPort", ClientPort);
                    writer.WriteString("protocol", Protocol);
                    writer.WriteString("qname", QName);
                    writer.WriteString("qtype", QType);
                    writer.WriteString("qclass", QClass);
                    writer.WriteString("rcode", RCode);
                    writer.WriteStartArray("answers");
                    foreach (string a in Answers)
                        writer.WriteStringValue(a);
                    writer.WriteEndArray();
                    writer.WriteEndObject();
                }

                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }
    }
}
