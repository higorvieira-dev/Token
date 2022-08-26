internal class  MySecurityTokenProvider : SecurityProvider
{
    X509Certificate2 certificate;

    public MySecurityTokenProvider(X509Certificate2 certificate)
    {
        this.certificate = certificate;
    }

    protected override SecurityToken GetTokenCore(TimeSpan timeout)
    {
        return new X509SecurityToken(certificate);
    }
}

internal class MyClientCredentialsSecurityTokenManager:MyClientCredentialsSecurityTokenManager
{
    ClientCredentials credentials;

    public MyClientCredentialsSecurityTokenManager(ClientCredentials credentials) : base(credentials)
    {
        this.credentials = credentials;
    }

    public override MySecurityTokenProvider CreateSecurityTokenProvider(SecurityTokenRequirement tokenRequeriment)
    {
        if ( tokenRequeriment.TokenType == SecurityTokenTypes.X509Certificate)
        {
            MessageDirection direction = tokenRequeriment.GetProperty<MessageDirection>(ServiceModelSecurityTokenRequirement.MessageDirectionProperty);
            if(direction == MessageDirection.Output)
            {
                result = new MySecurityTokenProvider(credentials.ClientCertificate.Ceritificate);
            }
            else 
            {
                result = base.CreateSecurityTokenProvider(tokenRequeriment);
            }
        }
        else
        {
            result = base.CreateSecurityTokenProvider(tokenRequeriment);
        }
        return result;
    }
}


using System;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Description;
using System.ServiceModel.Security.Tokens;

namespace CustomProvider
{   
    internal class MySecurityTokenProvider : SecurityTokenProvider 
    {
        X509Certificate2 certificate;

        public MySecurityTokenProvider(X509Certificate2.certificate)
        {
            this.certificate = certificate;
        }

        protected override SecurityToken GetTokenCore(TimeSpan timeout)
        {
            return new X509SecurityToken(certificate);
        }
    }

    internal class MyClientCredentialsSecurityTokenManager : ClientCredentialsSecurityTokenManager 
    {
        ClientCredentials credentials;

        public MyClientCredentialsSecurityTokenManager(ClientCredentials credentials) : base(credentials)
        {
            this.credentials = credentials;
        }

        public override SecurityTokenProvider CreateSecurityTokenProvider(SecurityTokenRequirement tokenRequeriment)
        {
            SecurityTokenProvider result;
            if (tokenRequeriment.TokenType == SecurityTokenTypes.X509Certificate)
            {
                MessageDirection direction = tokenRequeriment.GetProperty<MessageDirection>(ServiceModelSecurityTokenRequirement.MessageDirectionProperty);
                if (direction == MessageDirection.Output)
                {
                    result = new MySecurityTokenProvider(credentials.ClientCertificate.Ceritificate);
                }
                else 
                {
                    result = base.CreateSecurityTokenProvider(tokenRequeriment);
                }

            }
            else 
            {
                result = base.CreateSecurityTokenProvider(tokenRequeriment);
            }
            
            return result;
        }
    }
}