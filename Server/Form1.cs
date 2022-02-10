using System.Globalization;
using System.Numerics;
using System.IO;
using RSAImplementation;
using SimpleTcp;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Server
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }
        SimpleTcpServer server;
        KeyPair kp;
        RSAEncrypt re = new RSAEncrypt();
        RSADecrypt rd = new RSADecrypt();
        int counter = 0;

        BigInteger cPk; 

        Key clientPK;
        private void btnStart_Click(object sender, EventArgs e)
        {
            server.Start();
            txtInfo.Text += $"Starting ....{Environment.NewLine}";
            btnStart.Enabled = false;
            btnSend.Enabled = true;
        }

        private void label1_Click(object sender, EventArgs e)
        {

        }

        private void Form1_Load(object sender, EventArgs e)
        {
            
            btnSend.Enabled = false;
            server = new SimpleTcpServer(txtIP.Text);
            server.Events.ClientConnected += Events_ClientConnected;
            server.Events.ClientDisconnected += Events_ClientDisconnected;
            server.Events.DataReceived += Events_DataReceived;

            //generate key pair
            KeyGenerate kg = new KeyGenerate();
            kp = kg.GenerateKey();

        }

        private void Events_DataReceived(object sender, DataReceivedEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate
            { 
                if (counter == 0)
                {
                    txtInfo.Text += $"{e.IpPort} {ASCIIEncoding.UTF8.GetString(e.Data)} {Environment.NewLine}";
                    txtInfo.Text += $"{Environment.NewLine}";
                    cPk = new BigInteger(e.Data);
                    clientPK = new Key(cPk); 
                } else 
                {
                    byte[] decText = rd.DecryptBytes(e.Data, kp.privateKey);
                    txtInfo.Text += $"{e.IpPort}: {ASCIIEncoding.UTF8.GetString(decText)} {Environment.NewLine}";
                }
                counter++;
            });
        }

        private void Events_ClientDisconnected(object sender, ConnectionEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate
            { 
                txtInfo.Text += $"{e.IpPort} Disconnected {Environment.NewLine}";
                listClientIp.Items.Remove(e.IpPort);
                txtInfo.Text += $"{cPk}";
            });
        }

        private void Events_ClientConnected(object sender, ConnectionEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate
            {             
                txtInfo.Text += $"{e.IpPort} Connected {Environment.NewLine}";
                server.Send(e.IpPort.ToString(),kp.publicKey.n.ToByteArray());
                listClientIp.Items.Add(e.IpPort);
            });
        }

        private void label3_Click(object sender, EventArgs e)
        {

        }
        private void btnSend_Click(object sender, EventArgs e)
        {
            if (server.IsListening)
            {
                if (!string.IsNullOrEmpty(txtMessage.Text) && listClientIp.SelectedItem != null)
                {
                    
                    byte[] encryptedTxt = re.EncryptBytes(txtMessage.Text,clientPK);
            
                    server.Send(listClientIp.SelectedItem.ToString(), encryptedTxt);
                    // txtInfo.Text += $"Server: {txtMessage.Text}{Environment.NewLine}";
                    txtInfo.Text += $"Server: {ASCIIEncoding.UTF8.GetString(encryptedTxt)} {Environment.NewLine}";
                    txtMessage.Text = string.Empty;
                }
            }
        }
        private void listClientIp_SelectedIndexChanged(object sender, EventArgs e)
        {

        }
    }
}
