
public class SignInWithModel 
{
    String clientId,redirectUri,scope,responseType,accessType,sendRefresh;

	@Override
	public String toString() {
		return "SignInWithModel [clientId=" + clientId + ", redirectUri=" + redirectUri + ", scope=" + scope
				+ ", responseType=" + responseType + ", accessType=" + accessType + ", sendRefresh=" + sendRefresh
				+ "]";
	}

	public String getSendRefresh() {
		return sendRefresh;
	}

	public void setSendRefresh(String sendRefresh) {
		this.sendRefresh = sendRefresh;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getRedirectUri() {
		return redirectUri;
	}

	public void setRedirectUri(String redirectUri) {
		this.redirectUri = redirectUri;
	}

	public String getScope() {
		return scope;
	}

	public void setScope(String scope) {
		this.scope = scope;
	}

	public String getResponseType() {
		return responseType;
	}

	public void setResponseType(String responseType) {
		this.responseType = responseType;
	}

	public String getAccessType() {
		return accessType;
	}

	public void setAccessType(String accessType) {
		this.accessType = accessType;
	}
}
