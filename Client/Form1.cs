using RSAImplementation;
using SimpleTcp;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Client
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        SimpleTcpClient client;
        KeyPair kp;
        int counter = 0;
        BigInteger cPk; 

        Key serverPk;
        RSADecrypt rd = new RSADecrypt();
        RSAEncrypt re = new RSAEncrypt();
        
        private void btnConnect_Click(object sender, EventArgs e)
        {
            try
            {
                client.Connect();
                btnSend.Enabled = true;
                btnConnect.Enabled = false;

                txtInfo.Text += $"{kp.publicKey} {Environment.NewLine}";
            }
            catch(Exception ex)
            {
                MessageBox.Show(ex.Message,"Message", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void label1_Click(object sender, EventArgs e)
        {
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            client = new SimpleTcpClient(txtIp.Text);
            client.Events.Connected += Events_Connected;
            client.Events.DataReceived += Events_DataRecieved;
            client.Events.Disconnected += Events_Disconnected;
            btnSend.Enabled = false;

            //Generate Key pair
            KeyGenerate kg = new KeyGenerate();
            kp = kg.GenerateKey();
        }

        private void Events_Disconnected(object sender, ConnectionEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate
            {
                txtInfo.Text += $"Server disconnected. {Environment.NewLine}";
            });
        }

        private void Events_DataRecieved(object sender, DataReceivedEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate
            {
                if (counter == 0)
                {
                    txtInfo.Text += $"Server: {ASCIIEncoding.UTF8.GetString(e.Data)} {Environment.NewLine}";
                    txtInfo.Text += $"{Environment.NewLine}";         
                    cPk = new BigInteger(e.Data);
                    serverPk = new Key(cPk);
                } else 
                {
                    txtInfo.Text += $"Server: {ASCIIEncoding.UTF8.GetString(e.Data)} {Environment.NewLine}";
                    byte[] decText = rd.DecryptBytes(e.Data, kp.privateKey);
                    txtInfo.Text += $"Server: {ASCIIEncoding.UTF8.GetString(decText)} {Environment.NewLine}";
                }
                counter++;
            });
        }

        private void Events_Connected(object sender, ConnectionEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate
            {
                txtInfo.Text += $"Server Connected. {Environment.NewLine}";
                client.Send(kp.publicKey.n.ToByteArray());
            });
        }

        private void btnSend_Click(object sender, EventArgs e)
        {
            if (client.IsConnected)
            {
                if (!string.IsNullOrEmpty(txtMessage.Text))
                {
                    byte[] encryptedTxt = re.EncryptBytes(txtMessage.Text,serverPk);
            
                    client.Send( encryptedTxt);
                    client.Send(txtMessage.Text);
                    // txtInfo.Text += $"Me: {txtMessage.Text} {Environment.NewLine}";
                    txtInfo.Text += $"Server: {ASCIIEncoding.UTF8.GetString(encryptedTxt)} {Environment.NewLine}";
                    txtMessage.Text = string.Empty;
                }
            }
        }
    }
}
