
public class EnhanceTokenModel 
{
    String clientId,refreshToken,enhanceToken,timestamp,scope;
    public EnhanceTokenModel(String clientId, String refreshToken, String enhanceToken, String timestamp, String scope,
			int uid) {
		super();
		this.clientId = clientId;
		this.refreshToken = refreshToken;
		this.enhanceToken = enhanceToken;
		this.timestamp = timestamp;
		this.scope = scope;
		this.uid = uid;
	}
	@Override
	public String toString() {
		return "EnhanceTokenModel [clientId=" + clientId + ", refreshToken=" + refreshToken + ", enhanceToken="
				+ enhanceToken + ", timestamp=" + timestamp + ", scope=" + scope + ", uid=" + uid + "]";
	}
	public String getClientId() {
		return clientId;
	}
	public void setClientId(String clientId) {
		this.clientId = clientId;
	}
	public String getRefreshToken() {
		return refreshToken;
	}
	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}
	public String getEnhanceToken() {
		return enhanceToken;
	}
	public void setEnhanceToken(String enhanceToken) {
		this.enhanceToken = enhanceToken;
	}
	public String getTimestamp() {
		return timestamp;
	}
	public void setTimestamp(String timestamp) {
		this.timestamp = timestamp;
	}
	public String getScope() {
		return scope;
	}
	public void setScope(String scope) {
		this.scope = scope;
	}
	public int getUid() {
		return uid;
	}
	public void setUid(int uid) {
		this.uid = uid;
	}
	int uid;
    
}
