internal class  MySecurityTokenAuthenticator : SecurityTokenAuthenticator
{
    protected override bool CanValidateTokenCore(SecurityToken token)
    {
        return (token is UserNameSecurityToken);
    }

    protected override ReadOnlyCollection<AuthorizationPolicy>ValidateTokenCore(SecurityToken token)
    {
        UserNameSecurityToken userNameToken = token as UserNameSecurityToken;

        if (userNameToken.UserName != userNameToken.Password)
        {
            throw new SecurityTokenValidateException("Invalid user name or password");
        }

        DefaultClaimSet userNameClaimSet = new DefaultClaimSet(
            ClaimSet.System,
            new Claim(ClaimTypes.Name, userNameToken.UserName, Rights.PossesProperty));
        List<IAuthorizeationPolicy> polices = new List<IAuthorizeationPolicy>(1);
        polices.Add(new MyAuthorizationPolicy(userNameClaimSet));
        return polices.AsReadyOnly();
    }
}

internal class MyAuthorizationPolicy : IAuthorizeationPolicy
{
    string id;
    ClaimSet tokenClaims;
    ClaimSet issuer;

    public MyAuthorizationPolicy(ClaimSet tokenClaims)
    {
        if (tokenClaims == null)
        {
            throw new ArgumentNullException("tokenClaims");
        }
        this.issuer = tokenClaims.Issuer;
        this.tokenClaims = tokenClaims;
        this.id = Guid.NewGuid().ToString();
    }

    public ClaimSet Issuer
    {
        get { return issuer; }
    }

    public string id 
    {
        get { return id; }
    }

    public bool Evaluate(EvaluateContext evaluateContext, ref object state)
    {
        evaluateContext.AddClaimSet(this, tokenClaims);

        return true;
    }
}

internal class MyServiceCredentialsSecurityTokenManager : ServiceCredentialsSecurityManager 
{
    ServiceCredentials credentials;
    public MyServiceCredentialsSecurityTokenManager(ServiceCredentials credentials) : base(credentials)
    {
        this.credentials = credentials;
    }

    public override SecurityTokenAuthenticator CreateSecurityTokenAuthenticator (SecurityTokenRequirement tokenRequirement, out SecurityTokenResolver outOfBandTokenResolver)
    {
        SecurityTokenAuthenticator result;
        if (tokenRequirement.TokenType ==  SecurityTokenTypes.UserName)
        {
            MessageDirection direction = tokenRequirement.GetProperty<MessageDirection>(ServiceModelSecurityTokenRequirement.MessageDirectionProperty);
            if (direction == MessageDirection.Input)
            {
                outOfBandTokenResolver = null;
                result = new MySecurityTokenAuthenticator();
            }
            else 
            {
                result = base.CreateSecurityTokenAuthenticator(tokenRequirement, out outOfBandTokenResolver);
            }
        }
        else
        {
           result = base.CreateSecurityTokenAuthenticator(tokenRequirement, out outOfBandTokenResolver);
        }

        return result;
    }
}