using System.Globalization;
using System.Numerics;
using System.IO;
using RSAImplementation;
using AESImplementation;
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
        AESEncrypt aEnc;
        AESDecrypt aDec;
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
            aEnc = new AESEncrypt();
            aDec =  new AESDecrypt();
            
            KeyGenerate kg = new KeyGenerate();
            kp = kg.GenerateKey(1024);

        }

        private void Events_DataReceived(object sender, DataReceivedEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate
            { 
                if (counter == 0)
                {
                    txtInfo.Text += $"-----Public Key of Client------ {Environment.NewLine}";
                    txtInfo.Text += $"{ASCIIEncoding.UTF8.GetString(e.Data)}";
                    txtInfo.Text += $"-------------------{Environment.NewLine} End of public key{Environment.NewLine}";
                    cPk = new BigInteger(e.Data);
                    clientPK = new Key(cPk); 
                } else 
                {
                    byte[] aesEKey = e.Data.Slice(0, 128); //127
                    byte[] aesKey = rd.DecryptBytes(aesEKey, kp.privateKey);
                    byte[] recievedETxt = e.Data.Slice(128, e.Data.Length);
                    byte[] recievedTxt = aDec.DecryptByte(recievedETxt, aesEKey);
                    txtInfo.Text += $"{e.IpPort}: {ASCIIEncoding.UTF8.GetString(recievedTxt)} {Environment.NewLine}";
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
                    byte[]  symKey = AESImplementation.Utility.GenerateRandomByte(16);
                    byte[] encryptedKey = re.EncryptBytes(symKey, clientPK);
                    byte[] encryptedTxt = aEnc.EncryptByte(ASCIIEncoding.UTF8.GetBytes(txtMessage.Text), encryptedKey);
                    byte[] toSend = encryptedKey.Concat(encryptedTxt).ToArray();
                    server.Send(listClientIp.SelectedItem.ToString(), toSend);
                    txtInfo.Text += $"Server: {txtMessage.Text} {Environment.NewLine}";
                    txtMessage.Text = string.Empty; 
                }
            }
        }
        private void listClientIp_SelectedIndexChanged(object sender, EventArgs e)
        {


        }
    }
}
