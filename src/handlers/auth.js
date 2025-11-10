import jwt from "jsonwebtoken";

const generatePolicy = (principalId, methodArn) => {
  const apiGatewayWildcard = methodArn.split("/", 2).join("/") + "/*";
  return {
    principalId,
    policyDocument: {
      Version: "2012-10-17",
      Statement: [
        {
          Action: "execute-api:Invoke",
          Effect: "Allow",
          Resource: apiGatewayWildcard,
        },
      ],
    },
  };
};

export async function handler(event) {
  if (!event.authorizationToken) {
    console.error("❌ No authorization token found");
    throw new Error("Unauthorized");
  }

  const token = event.authorizationToken.replace("Bearer ", "");

  try {
    const claims = jwt.verify(token, process.env.AUTH0_PUBLIC_KEY, {
      algorithms: ["RS256"],
      issuer: "https://dev-i1w2y7423dkuo7fv.us.auth0.com/",
      audience: [
        "https://dev-i1w2y7423dkuo7fv.us.auth0.com/api/v2/",
        "https://dev-i1w2y7423dkuo7fv.us.auth0.com/userinfo",
      ],
      ignoreExpiration: false,
    });

    const policy = generatePolicy(claims.sub, event.methodArn);

    if (Array.isArray(claims.aud)) {
      claims.aud = claims.aud[0];
    }

    return {
      ...policy,
      context: claims,
    };
  } catch (error) {
    console.error("❌ Error al verificar JWT:", {
      message: error.message,
      name: error.name,
      stack: error.stack,
    });
    throw new Error("Unauthorized");
  }
}
