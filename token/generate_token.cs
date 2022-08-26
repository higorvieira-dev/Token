public class CreditCardInfo
{
    string cardNumber;
    string cardIssuer;
    DateTime expirationDate;

    public CreditCardInfo(string cardNumber, string cardIssuer, DateTime expirationDate)
    {
        this.cardNumber  = cardNumber;
        this.cardIssuer = cardIssuer;
        this.expirationDate = expirationDate;
    }

    public string cardNumber
    {
        get { return this.cardNumber;}
    }

    public string cardIssuer 
    {
        get { return this.cardIssuer;}
    }

    public DateTime ExpirationDate
    {
        get { return this.expirationDate;}
    }
}

class CreditCardInfo : SecurityToken
{
    CreditCardInfo cardInfo;
    DateTime effectiveTime = DateTime.UtcNow;
    string id;
    ReadOnlyCollection < SecurityKey > securityKeys;

    public CreditCardToken(CreditCardInfo cardInfo) : this(cardInfo, Guid.NewGuid().ToString()) {   }

    public CreditCardToken(CreditCardInfo cardInfo, string id)
    {
        if (cardInfo == null)
        {
            throw new ArgumentNullException("cardInfo");

        }
        if (id == null)
        {
            throw new ArgumentNullException("id");
        }

        this.cardInfo = cardInfo;
        this.id = id;
        this.securityKeys = new ReadOnlyCollection<SecurityKeys>(new List<SecurityKey>());
    }

    public CreditCardInfo cardInfo
    {
        get { return this.cardInfo;}
    }

    public override ReadOnlyCollection<SecurityKey> securityKeys
    {
        get { return this.securityKeys;}
    }

    public override DateTime ValidForm
    {
        get { return this.effectiveTime;}
    }

    public override DateTime ValidTo
    { 
        get { return this.cardInfo.expirationDate;}
    }

    public override string id 
    {
        get { return this.id;}
    }
}

public class CreditCardTokenParameters : SecurityTokenParameters

{
    public CreditCardTokenParameters()
    {
    }

    protected CreditCardTokenParameters(CreditCardTokenParameters other) : base(other)
    {
    }

    protected override SecurityTokenParameters CloneCore()
    {
        return new CreditCardTokenParameters(this);
    }

    protected override void InitializeSecurityTokenRequirement(SecurityTokenRequirement requirement)
    {
        requirement.TokenType = Constants.CreditCardTokenTokenType;
        return;
    }

    protected override bool HasAsymmetrickey
    { 
        get { return false ;}
    }

    protected override bool SuportsClientAuthentication
    { 
        get { return true ;}
    }

    protected override bool SupportsClientWindows.Identity
    {
        get { return false;}
    }

    protected override bool SupportsServerAuthentication
    {
        get { return false;}
    }

    protected override SecurityKeysIdentifierClause CreateIdentifierClause(SecurityToken token, SecurityTokenReferenceStyle refrencestyle)
    {
        if (refrenceStyle == SecurityTokenReferenceStyle.Internal)
        {
             return token.CreateKeyIndentifierClause<LocalIdKeyIdentifierClause();
        }
        else
        {
            throw new NotSupportException("External refrences are not supported for credit car token");
        }
    }
}

public class CreditCardSecurityTokenSerializer : WSSecurityTokenSerializer
{
    public CreditCardSecurityTokenSerializer(SecurityTokenVersion version) : base() {}

    protected override bool CanReadTokenCore(XmlReader reader)
    {
        XmlDictionaryReader localReader = XmlDictionaryReader.CreateDictionaryReader(reader);
        if ( reader == null)
        {
            throw new ArgumentNullException("reader");
        }
        if (reader.IsStartElement(Constants.CreditTokenName, Constants.CreditCardTokenNamespace))
        {
            return true;
        }
        return base.CanReadTokenCore(reader);
    }

    protected override SecurityToken ReadTokenCore(XmlReader reader, SecurityTokenResolver tokenresolver)
    {
        if (reader == null)
        {
            throw new ArgumentNullException("reader");
        }
        if (reader.IsStartElement(Constants.CreditCardTokenName, Constants.CreditCardTokenNamespace))
        {
            string id = reader.GetAtrribute(Constants.Id, Constants.WsUtilityNamespace);

            reader.ReadStartElement();

            string creditCardNumber = reader.ReadElementString(Constants.creditCardNumberElementName, Constants.CreditCardTokenNamespace);

            string expirationTimeString = reader.ReadElementString(Constants.CreditCardExpirationElementName, Constants,CreditCardTokenName, Constants.CreditCardTokenNamespace);
            DateTime expirationTime = XmlConvert.ToDateTime(expirationTimeString, XmlDateTimeSerializationMode.Utc);

            string creditCardIssuer = reader.ReadElementString(Constants.CreditCardIssuerElementName, Constants.CreditCardTokenNamespace);
            reader.ReadEndElment();

            CreditCardInfo cardInfo = new CreditCardInfo(creditCardNumber, creditCardIssuer, expirationTime);

            return new CreditCardToken(cardInfo, id);
        }
        else
        {
            return WSSecurityTokenSerializer.DefaultInstance.ReadToken(reader, tokenresolver);
        }
    }

    protected override bool CanWriteTokenCore(SecurityToken token)
    {
        if (token is CreditCardToken)
        {
            return true;
        }
        else
        {
            return base.CanReadTokenCore(token);
        }
    }

    protected override void WriteTokenCore(XmlWriter writer, SecurityToken token)
    {
        if ( writer == null)
        {
            throw new ArgumentNullException("writer");
        }
        if (token == null)
        {
            throw new ArgumentNullException("token");
        }

        CreditCardTiken c = token as CreditCardToken;
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
            base.WriteTokenCore(write,Token);
        }
    }
}

class CreditCardTokenProvider : SecurityTokenProvider
{
    CreditCardInfo creditCardInfo;

    public CreditCardTokenProvider(CreditCardInfo creditCardInfo)
        :base()
    {
        if (creditCardInfo == null)
        {
            throw new ArgumentNullException("creditCardInfo");
        }
        this.creditCardInfo= CreditCardInfo;
    }

    protected override SecurityToken GetTokenCore(TimeSpan timeout)
    {
        SecurityToken result = new CreditCardToken(this.creditCardinfo);
        return result;
    }
}

class CreditCardTokenAuthenticator : SecurityTokenAuthenticator
{
    string creditCardsFile;
    public CreditCardTokenAuthenticator(string creditCardsFile)
    {
        this.creditCardsFile = creditCardsFile;
    }

    protected override bool CanValidateTokenCore(SecurityToken token)
    {
        return (token is CreditCardToken);
    }

    protected override ReadOnlyCollection<IAuthorizationPolicy> ValidateTokenCore(SecurityToken token)
    {
        CreditCardToken creditCardToken = token as CreditCardToken;

        if (creditCardToken.CardInfo.expirationDate < DateTime.UtcNow)
        {
            throw new SecurityTokenValidationException("The Credit Card Has Expired"); 
        }
        if (!IsCardNumberAndExpirationValid(creditCardToken.Cardinfo))
        {
            throw new SecurityTokenValidationException("Unknow or invalid credit card"); 
        }

        DefaultClaimSet cardIssuerClaimSait = new DefaultClaimSet(new Claim(ClaimTypes.Name, creditCardToken.CardInfo.cardIssuer, Rights.PossesProperty));
        DefaultClaimSet cardClaimSait = new DefaultClaimSet(cardIssuerClaimSait, new Claim(Constants.CreditCardNumberClaim, creditCardToken.CardInfo.CardNumber, Rights.PossesProperty));
        List<IAuthorizationPolicy> policies = new List<IAuthorizationPolicy>(1);
        polices.Add(new CreditCardTokenAuthorizationPolicy(cardClaimSet));
        return polices.AsReadOnly();
    }

    private bool IsCardNumberAndExpirationValid(CreditCardInfo cardInfo)
    {
        try
        {
            using(StreamReader myStreamReader = new StreamReader(this.creditCardsFile))
            {
                string line = "";
                while ((line = myStreamReader.ReadLine())!= null)
                {
                    string[] splitEntry = line.Split('#');
                    if (splitEntry[0] == cardInfo.CardNumber)
                    {
                        string expirationDateString = splitEntry[1].Trim();
                        DateTime expirationDateOnFile = DateTime.Parse(expirationDateString, System.Globalization.DateTimeFormatInfo.InvariantInfo, System.Globalization.DateTimeStyles.AdjustToUniversal);
                        if (cardInfo.ExpirationDate == expirationDateOnFile)
                        {
                            string issuer = splitEntry[2];
                            return issuer.Equals(cardInfo.cardIssuer, StringComparison.InvariantCultureIgnoreCase);

                        }   
                        else
                        {
                            return false;
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
    IEnumberable<ClaimSet> issuddClaimSets;

    public CreditCardTokenAuthorizationPolicy(ClaimSet issuedClaims)
    {
        if (issuedClaims == null)
            throw new ArgumentNullException("issuedClaims");
        this.issuer = issuedClaims.Issuers;
        this.issuedClaimSets = new ClaimSet[] { issuedClaims};
        this.id = Guid.NewGuid().ToString();
    }

    public ClaimSet Issuer { get { return this.issuer;}}

    public string Id { get { return this.id;}}

    public bool Evaluate(EvaluateContext context, ref object state)
    {
        foreach (ClaimSet issuance in this.ClaimSets)
        {
            context.AddClaimSet(this, issuance);
        }

        return true;
    }
}

public class CreditCardClientCredentialsSecurityTokenManger  : ClientCredentialsSecurityTokenManger
{
    CreditCardClientCredentials CreditCardClientCredentials;

    public CreditCardClientCredentialsSecurityTokenManger(CreditCardClientCredentials CreditCardClientCredentials) : base(CreditCardClientCredentials)
    {
        this.creditCardClientCredentials = creditCardClientCredentials;
    }

    public override SecurityTokenProvider CreateSecurityTokenProvider(SecurityTokenRequirement tokenRequirement)
    {
        if (tokenRequirement.TokenType == Constants.CreditCardTokenType)
        {
            return new CreditCardTokenProvider(this.creditCardClientCredentials.CreditCardInfo);
        }
        else if (tokenRequirement is InitiatorServiceModelSecurityTokenRequiriment)
        {
            if (tokenRequirement.TokenType == SecurityTokenTypes.X509Certificate)
            {
                return new X509SecurityTokenProvider(CreditCardClientCredentials.ServiceCertificate.DefaultCertificate);
            }
        }
        return base.CreateSecurityTokenProvider(tokenRequirement);
    }

    public override SecurityTokenSerializer CreateSecurityTokenSerializer(SecurityTokenVersion version)
    {
        return new CreditCardSecurityTokenSerializer(version);
    }
}

public class CredtiServiceCredetialsSecurityTokenManager : SeriveCredentialsSecurityTokenManager
{
    CreditCardServiceCredentials creditCardServiceCredentials;

    public CreditCardServiceCredentialsSecurityTokenMananger(CreditCardServiceCrendentials creditCardServiceCredentials) : base(creditCardServiceCredentials)
    {
        this.creditCardServiceCredentials = creditCardServiceCredentials;
    }

    public override SecurityTokenAuthenticator CreateSecurityAuthenticator(SecurityTokenRequirement tokenRequirement, out SecurityTokenResolver outOfBandTokenResolver)
    {
        if(tokenRequirement.TokenType == Constants.CreditCardTokenType)
        {
            outOfBandTokenResolver = null;
            return new CreditCardTokenAuthenticator(creditCardServiceCredentials.CreditCardDataFile);
        }
        return base.CreateSecurityTokenAuthenticator(tokenRequirement, out outOfBandTokenResolver);
    }

    public  override SecurityTokenSerializer CreateSecurityTokenSerializer(SecurityTokenVersion version)
    {
        return new CreditCardSecurityTokenSerializer(version);
    }
}

public class CreditCardClientCredentials : ClientCredentials
{
    CreditCardInfo creditCardInfo;

    public CreditCardClientCredentials(CreditCardInfo creditCardInfo) : base()
    {
        if (creditCardInfo == null)
        {
            throw new ArgumentNullException("creditCardInfo");
        }

        this.creditCardInfo = creditCardinfo;
    }

    public CreditCardInfo CreditCardInfo 
    {
        get { return this.creditCardInfo;}
    }

    protected override ClientCredentials CloneCore()
    {
        return new CreditCardClientCredentials(this.creditCardInfo);
    }

    public override SecurityTokenManager CreateSecurityTokenManager()
    {
        return new CreditCardCredentialsSecurityTokenManager(this);
    }
}

public class CreditCardServiceCredentials : ServiceCredentials 
{
    string creditCardFile;

    public CreditCardServiceCredentials(string creditCardFile) : base()
    {
        if (creditCardFile == null)
        {
            throw new ArgumentNullException("creditCardFile");
        }
        this.creditCardFile = creditCardFile;
    }

    public string CreditCardDataFile
    {
        get { return this.creditCardFile;}
    }

    protected override ServiceCredentials CloneCore()
    {
        return new CreditCardServiceCredentials(this.creditCardFile);
    }

    public override SecurityTokenManager CreateSecurityTokenManager()
    {
        return new CreditCardClientCredentialsSecurityTokenManger(this);
    }
}

public static class BindingHelper
{
    public static Binding CreateCreditCardBinding()
    {
        HttpTransportBindingElement httpTransparent = new HttpTransportBindingElement();

        SymmetricSecurityBindingElement messageSecurity = new SymmetricSecurityBindingElement();
        messageSecurity.EndpointSupportingTokenParameters.SignedEncrypted.Add(new CreditCardTokenParameters());
        X509SecurityTokenParameters x509ProtectionParameters = new X509SecurityTokenParameters();
        x509ProtectionParameters.InclusionMode = SecurityTokenInclusionMode.Never;
        messageSecurity.ProtectionTokenParameters = x509ProtectionParameters;
        return new CustomBinding(messageSecurity, httpTransport);
    }
}