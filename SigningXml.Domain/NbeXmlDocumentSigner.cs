using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

namespace SigningXml
{
    public class NbeXmlDocumentSigner
    {
        public static byte[] SignBodyParameter(XmlDocument doc, RSA key)
        {
            var responseXml = doc.GetElementsByTagName("xml")[0];

            var docForSign = new XmlDocument();
            docForSign.LoadXml(responseXml.InnerText);

            if (docForSign.FirstChild.Name == "xml")
                docForSign.RemoveChild(docForSign.FirstChild);

            var signedXml = new SignedXml
            {
                SigningKey = key
            };

            var objectID = docForSign.FirstChild.Name;
            var dataObject = new DataObject
            {
                Data = docForSign.ChildNodes,
                Id = objectID
            };

            signedXml.AddObject(dataObject);

            signedXml.AddReference(new Reference($"#{objectID}"));

            signedXml.ComputeSignature();

            //var realXml = signedXml.GetXml().OuterXml;

            //var el = new XElement("Root", realXml);
            //responseXml.InnerXml = el.LastNode.ToString();

            //responseXml.InnerXml = System.Web.HttpUtility.HtmlEncode(signedXml.GetXml().OuterXml);

            var s = System.Security.SecurityElement.Escape(signedXml.GetXml().OuterXml);

            
            responseXml.InnerText = System.Security.SecurityElement.Escape(signedXml.GetXml().OuterXml);

            //new XmlElement()

            //responseXml.InnerXml = signedXml.GetXml().OuterXml.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("&#34;", "&quot;").Replace("'", "&apos;");

            return signedXml.SignatureValue;
        }

        public static (string signedEnvelope, byte[] signature) SignBodyParameter(string envelope, RSA key)
        {
            var doc = new XmlDocument();
            doc.LoadXml(envelope);
            var responseXml = doc.GetElementsByTagName("xml")[0];

            var docForSign = new XmlDocument();
            docForSign.LoadXml(responseXml.InnerText);

            if (docForSign.FirstChild.Name == "xml")
                docForSign.RemoveChild(docForSign.FirstChild);

            var signedXml = new SignedXml
            {
                SigningKey = key
            };

            var objectID = docForSign.FirstChild.Name;
            var dataObject = new DataObject
            {
                Data = docForSign.ChildNodes,
                Id = objectID
            };

            signedXml.AddObject(dataObject);

            signedXml.AddReference(new Reference($"#{objectID}"));

            signedXml.ComputeSignature();

            var securityElement = SecurityElement.FromString(envelope);

            var k = securityElement.SearchForChildByTag("s:Body").SearchForChildByTag("RegisterResponse").SearchForChildByTag("xml");
            k.Text = SecurityElement.Escape(signedXml.GetXml().OuterXml);

            return (securityElement.ToString(), signedXml.SignatureValue);
        }

        public static bool ValidateSignature(XmlDocument xmlDoc, RSA publicKey)
        {
            //try
            //{
                xmlDoc.PreserveWhitespace = true;

                var signedXmlObj = new SignedXml(xmlDoc);

                var nodeList = xmlDoc.GetElementsByTagName("Signature");
                signedXmlObj.LoadXml((XmlElement)nodeList[0]);

                return signedXmlObj.CheckSignature(publicKey);
            //}
            //catch
            //{
            //    return false;
            //}
        }

        public static RSA GetPrivateKeyFromPath(string privateKeyPath, string privateKeyPassword) => new X509Certificate2(privateKeyPath, privateKeyPassword).GetRSAPrivateKey();

        public static RSA GetPublicKeyFromPath(string publicKeyPath)
        {
            var bytesArr = File.ReadAllBytes(publicKeyPath);
            var collection = new X509Certificate2Collection();
            collection.Import(bytesArr);
            //return (RSACryptoServiceProvider)collection[0].PublicKey.Key;//.GetRSAPublicKey();
            return collection[0].GetRSAPublicKey();
            //return new X509Certificate2(publicKeyPath).GetRSAPublicKey();
        }
    }
}
