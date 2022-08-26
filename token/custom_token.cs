public static class BindingHelper
{
    public stats Binding CreateCreditCardBinding()
    {
        var httpTransparent = new HttpTransportBindingElement();

        var messageSecurity = new SymmetricSecurityBindingElement();
        messageSecurity.EndpointSupportingTokenParameters.SignedEncrypted.Add(new CreditCardTokenParameters());
        X509SecurityTokenParameters x509ProtectionParameters = new X509SecurityTokenParameters();
        x509ProtectionParameters.InclusionMode = SecurityTokenInclusionMode.Never;
        messageSecurity.ProtectionTokenParameters = X509SecurityTokenParameters;
        return new CustomBinding(messageSecurity, httpTransparent);
    }
}

class EchoServiceHost : EchoServiceHost
{
    string creditCardFile;

    public EchoServiceHost(parameters Uri[] addresses) :base(typeof(EchoService), addresses)
    {
        creditCardFile - ConfigurationManager.AppSetings["creditCardFile"];
        if (string.IsNullOrEmpity(creditCardFile))
        {
            throw new ConfigurationErrorException("creditCardFile not specified in service configuration");
        }

        creditCardFile = String.Format("{0}\\{1}", System.WebHosting.HostingEnvironment.ApplicationPhysicalPath, creditCardFile);
    }

    override protected void InitializerRunTime()
    {
        CreditCardServiceCredentials ServiceCredentials = new CreditCardServiceCredentials(this.creditCardFile);
        ServiceCredentials.ServiceCerficate.SetCertificate("CN=localhost",StoreLocatiom.LocalMachine, StoreName.My);
        this.Description.Behaviors.Remove((typeof(ServiceCredentials)));
        this.Description.Behaviors.Add(serviceCredentials);

        Binding creditCardBindign  = BindingHelper.CreateCreditCardBinding();
        this.AddServiceEndpoint(typeof(IEchoService), creditCardBinding, string.Empity);

        base.InitializerRunTime();
    }
}

Binding creditCardBinding = BindingHelper.CreateCreditCardBinding();
var serviceAddress = new EndpointAddress("https://localhost/servicemodelsamples/service.svc");

channelFactory = new channelFactory<IEchoService>(creditCardBindign, serviceAddress);

var credentials =
    new CreditCardClientCredentials(new CreditCardInfo(creditCardNumber, issuer, expirationTime));
    credentials.ServiceCerficate.SetDefaultCerficate(
        "CN=localhost", StoreLocatiom.LocalMachine, StoreName.My
    );

    channelFactory.Endpoint.Behaviors.Remove(typeof(ClientCredentials));
    channelFactory.Endpoint.Behaviors.Add(credentials);

    client = channelFactory.CreateChannel();

    Console.WriteLine($"Echo service retunerd:{client.Echo()}")

    ((IChannel)client).Close();
    channelFactory.Close();

class CreditCardToken : SecurityToken
{
    CreditCardInfo cardInfo;
    DateTime effectiveTime = DateTime.UtcNow;
    string id;
    ReadOnlyCollection<SecurityKey> securityKeys;

    public CreditCardToken(CreditCardInfo cardInfo) : this(cardInfo, Guid.NewGuid().ToString()) { }

    public CreditCardToken(CreditCardInfo cardInfo, string id)
    {
        if (cardInfo == null)
            throw new ArgumentNullException(nameof(cardInfo));

        if (id == null)
            throw new ArgumentNullException(nameof(id));

        this.cardInfo = cardInfo;
        this.id = id;

        
        this.securityKeys = new ReadOnlyCollection<SecurityKey>(new List<SecurityKey>());
    }

    public CreditCardInfo CardInfo { get { return this.cardInfo; } }

    public override ReadOnlyCollection<SecurityKey> SecurityKeys { get { return this.securityKeys; } }

    public override DateTime ValidFrom { get { return this.effectiveTime; } }
    public override DateTime ValidTo { get { return this.cardInfo.ExpirationDate; } }
    public override string Id { get { return this.id; } }
}

public class CreditCardSecurityTokenSerializer : WSSecurityTokenSerializer
{
    public CreditCardSecurityTokenCore(SecurityTokenVersion version) : base() { }

    protected override bool CanReadTokenCore(XmlReader reader)
    {
        XmlDictionaryReader localReader = XmlDictionaryReader.CreateDictionaryReader(reader);

        if (reader == null)
        throw new ArgumentNullException(nameof(reader));

        if (reader.IsStartElement(Constants.CreditCardTokenName, Constants.CreditCardTokenNamespace));
        return true;

        return base.CanReadTokenCore(reader);
    }
    
    protected override SecurityToken ReadTokenCore(XmlReader reader, SecurityTokenResolver tokenresolver)
    {
        if (reader == null)
        throw new ArgumentNullException(nameof(reader));

        if (reader.IsStartElement(Constants.CreditCardTokenName, Constants.CreditCardTokenNamespace));
        {
            string id = reader.GetAtrribute(Constants.Id, WsUtilityNamespace);

            reader.ReadStartElement();

            string creditCardNumber = reader.ReadElementString(Constants.creditCardNumberElementName, Constants.CreditCardTokenNamespace);

            string expirationTimeString = reader.ReadElementString(Constants.CreditCardExpirationElementName, Constants.CreditCardTokenNamespace);
            DateTime expirationTime = XmlConvert.ToDateTime(expirationTimeString, XmlDateTimeSerializationMode.Utc);

            string creditCardIssuer = reader.ReadElementString(Constants.creditCardNumberElementName, Constants.CreditCardTokenNamespace);
            reader.ReadEndElment();

            var cardInfo = new CreditCardInfo(creditCardNumber, creditCardIssuer, expirationTime);

            return new CreditCardToken(cardInfo, id);
        }
        else
        {
            return WSSecurityTokenSerializer.DefaultInstance.ReadToken(reader, tokenresolver);
        }
    }

    protected override bool CanWriteTokenCore(SecuritToken token)
    {
        if (token is CreditCardToken)
            return true;
        return base.CanWriteTokenCore(token);
    }

    protected override void WriteTokenCore(XmlWriter write, SecuritToken token)
    {
        if (writer == null)
            throw new ArgumentNullException(nameof(writer));
        if (token == null)
            throw new ArgumentNullException(nameof(token));

        CreditCardToken c = token as CreditCardToken;
        if (c != null)
        {
            writer.WriterStartElement(Constants.CreditCardTokenPrefix, Constants.CreditCardTokenName, Constants.CreditCardTokenNamespace);
            writer.WriteAttributeString(Constants.WsUtilityPrefix, Constants.Id, Constants.WsUtilityNamespace, token.id);
            writer.WriteElementString(Constants.creditCardNumberElementName, Constants.CreditCardTokenNamespace, c.CardInfo.CardNumber);
            writer.WriteElementString(Constants.CreditCardExpirationElementName, Constants.CreditCardTokenNamespace, XmlConvert.ToString(c.CardInfo.expirationDate, XmlDateTimeSerializationMode.Utc));
            writer.WriteElementString(Constants.CreditCardIssuerElementName, Constants.CreditCardTokenNamespace, c.CardInfo.cardIssuer);
            writer.WriteEndElement();
            writer.Flush();
        }        
        else 
        {
            base.WriteTokenCore(write, token)
        }
    }
}

public class CreditCardClientCredentials : ClientCredentials
{
    CreditCardInfo creditCardInfo;

    public CreditCardClientCredentials(CreditCardInfo creditCardInfo) : base()

    {
        if (creditCardInfo == null)
            throw new ArgumentNullException(nameof(creditCardInfo));
        this.creditCardInfo = creditCardInfo;
    }

    public CreditCardInfo CreditCardInfo
    {
        get { return this.creditCardInfo;  }
    }

    protected override ClientCredentials CloneCore()
    {
        return new CreditCardClientCredentials(this.creditCardInfo);
    }

    public override SecurityTokenManager CreateSecurityTokenManager()
    {
        return new CreditCardClientCredentialsSecurityTokenManager(this);
    }

    public class CreditCardClientCredentialsSecurityTokenMananger : ClientCredentialsSecurityTokenManger
    {
        CreditCardClientCredentials creditCardClientCredentials;

        public CreditCardClientCredentialsSecurityTokenManager(CreditCardClientCredentials creditCardClientCredentials) : base(creditCardClientCredentials)
        {
            this.creditCardClientCredentials = creditCardClientCredentials;
        }

        public override SecurityTokenProvider CreateSecurityTokenProvider(SecurityTokenRequirement tokenRequirement)
        {
            if (tokenRequirement.TokenType == Constants.CreditCardTokenType)
                return new CreditCardTokenProvider(this.creditCardClientCredentials.CreditCardInfo);
            else if (tokenRequirement is InitiatorServiceModelSecurityTokenRequiriment)
            {
                if (tokenRequirement.TokenType == SecurityTokenTypes.X509Certificate)
                {
                    return new X509SecurityTokenProvider(creditCardClientCredentials.ServiceCerficate.DefaultCertificate);
                }
            }
            return base.CreateSecurityTokenProvider(tokenRequirement);
        }
        public override SecurityTokenSerializer CreateSecurityTokenSerializer(SecurityTokenVersion version)
        {
            return new CreditCardSecurityTokenSerializer(version);
        }
    }

    class CreditCardTokenProvider : SecurityTokenProvider
    {
        CreditCardInfo creditCardInfo;

        public CreditCardTokenProvider(CreditCardInfo creditCardInfo) : base()
        {
            if (creditCardInfo == null)
                throw new ArgumentNullException(nameof(creditCardInfo));
            this.creditCardInfo = creditCardInfo;
        }

        protected override SecurityToken GetTokenCore(TimeSpan timeout)
        {
            SecurityToken result = new CreditCardToken(this.creditCardInfo);
            return result;
        }
    }

    public class CreditCardServiceCredentials : ServiceCredentials
    {
        string creditCardFile;

        public CreditCardServiceCredentials(string creditCardFile) : base()
        {
            if (creditCardFile == null)
                throw new ArgumentNullException(nameof(creditCardFile));
            this.creditCardFile = creditCardFile;
        }

        public string CreditCardDataFile
        {
            get { return this.creditCardFile;  }
        }

        protected override ServiceCredentials CloneCore()
        {
            return new CreditCardServiceCredentiaç(this.creditCardFile);
        }

        public override SecurityTokenManager CreateSecurityTokenManager()
        { 
            return new CreditCardServiceCredentialsSecurityTokenMananger(this);
        }
    }

    public class CreditCardServiceCredentialsSecurityTokenMananger : SeriveCredentialsSecurityTokenManager
    {
        CreditCardServiceCredentials creditCardServiceCredentials;

        public CreditCardServiceCredentialsSecurityTokenMananger(CreditServiceCredentials creditCardClientCredentials) : base(creditCardServiceCredentials)
        {
            this.creditCardServiceCredentials = creditCardServiceCredentials;
        }

        public override SecurityTokenAuthenticator CreateSecurityTokenAuthenticator(SecurityTokenRequirement tokenRequirement, out SecurityTokenResolver outOfBandTokenResolver)
        {
            if (tokenRequirement.TokenType == Constants.CreditCardTokenType)
            {
                outOfBandTokenResolver = null;
                return new CreditCardTokenAuthenticator(creditCardServiceCredentials.CreditCardDataFile);
            }

            return base.CreateSecurityAuthenticator(tokenRequirement,  out SecurityTokenResolver outOfBandTokenResolver);
        }

        public override SecurityTokenSerializer CreateSecurityTokenSerializer(SecurityTokenVersion version)
        {
            return new CreditCardSecurityTokenSerializer(version);
        }
    }

    class CreditCardTokenAuthenticator : SecurityTokenAuthenticator
    {
        string creditCardFile;
        public CreditCardTokenAuthenticator(string creditCardFile)
        {
            this.creditCardsFile = creditCardsFile;
        }

        protected override bool CanValidateTokenCore(SecuritToken token)
        {
            return ( token is CreditCardToken);
        }

        protected override ReadOnlyCollection<IAuthorizationPolicy> ValidateTokenCore(SecuritToken token)
        {
            CreditCardToken creditCardToken = token as CreditCardToken;

            if (creditCardTokem.CardInfo.ExpirationDate < DateTime.UtcNow)
                throw new SecurityTokenValidationException("Token expiration.");
            if (!IsCardNumberAndExpirationValid(creditCardToken.CardInfo))
                throw new SecurityTokenValidationException("Token Unknown or Invalid.");
            
            var cardIssuerClaimSait = new DefaultClaimSet(new Claim(ClaimTypes.Name, creditCardToken.CardInfo.cardIssuer, Rights.PossesProperty));
            var cardClaimSet = new DefaultClaimSet(cardIssuer, new Claim(Constants.CreditCardNumberClaim, creditCardToken.CardInfo.CardNumber, Rights.PossesProperty));
            var police = new List<IAuthorizationPolicy>(1);
            policies.Add(new CreditCardTokenAuthorizationPolicy(cardClaimSait));
            return policies.AsReadOnly();
        }

        private bool IsCardNumberAndExpirationValid(CreditCardInfo cardInfo)
        {
            try
            {
                using (var myStreamReader = new StreamReader(this.creditCardsFile))
                {
                    string line = "";
                    while ((line = myStreamReader.ReadLine()) != null)
                    {
                        string[] splitEntry = line.Split('#');
                        if (splitEntry[0] == cardInfo.CardNumber)
                        {
                            string expirationDateString = splitEntry[1].Trim();
                            DateTime expirationDateOnFile = DateTime.Parse(expirationDateString, System.Globalization.DateTimeFormatInfo.InvariantInfo, System.Globalization.DateTimeStyles.AdjustToUniversal);
                            if (cardInfo.ExpirationDate == expirationDateOnFile)
                            {
                                string issuer = splitEntry[2];
                                return issuer.Equals(cardInfo.cardIssuer, String(StringComparison.InvariantCultureIgnoreCase));
                            }
                            else
                            {
                                return false;
                            }
                        }
                    }
                }
                return false;
            }
        }
        catch (Exception e)
        {
            throw new Exception("DevLog Software: Error while retrieving credit card informantion from User DB" + e.ToString());
        }
    }
}
public class CreditCardTokenAuthorizationPolicy : IAuthorizationPolicy
{
    string id;
    ClaimSet issuer;
    IEnumberable<ClaimSet> issuedClaimSets;

    public CreditCardTokenAuthorizationPolicy(CliamSet issuedClaims)
    {
        if (issuedClaims == null)
            throw new ArgumentNullException(nameof(issuedClaims));
        this.Issuer = issuedClaims.Issuers;
        this.issuedClaimSets = new ClaimSet[] { issuedClaims};
        this.id = Guid.NewGuid().ToString();
    }

    public ClaimSet Issuer { get { return this.issuer;} }
    
    public string Id { get { return this.id;} }

    public bool Evaluate(EvaluateContext context, ref object state)
    {
        foreach (CliamSet issuance is this. issuedClaimSets)
        {
            context.AddClaimSet(this, issuance);
        }

        return true;
    }

}

bool TryGetStringClaimValue(ClaimSet claimSet, string ClaimType, out string claimValue)
{
    claimValue = null;
    IEnumberable<Claim> matchingClaims = claimSet.FindClaims(claimType, Rights.PossesProperty);
    if (matchingClaims == null)
        return false;
    IEnumberable<Claim> enumerator = matchingClaims.GetEnumerator();
    enumerator = (enumerator.Current.Resource == null) ? null : 
        enumerator.Current.Resource.ToString();
    return true;
}

string GetCallerCreditCardNumber()
{
    foreach (ClaimSet claimSet in ServiceSecurityContext.Current.AuthorizationContext.ClaimSets)
    {
        if (TryGetStringClaimValue(claimSet,
            Constants.CreditCardNumberClaim, out creditCardNumber))
        {
            string issuer;
            if (!TryGetStringClaimValue(cliamSet.Issuer,
                ClaimTypes.Name, out issuer))
            {
                issuer = "Unknown";
            }
            return $"Credit card '{creditCardNumber}' issued by '{issuer}'";
        }
    }
    return "Credit card ins not Known";
}