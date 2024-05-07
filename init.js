import jsonld from 'jsonld/lib/jsonld.js';
import { CompactSign, importPKCS8 } from 'jose'
import crypto from 'crypto'

import vcCtx from "./public/credentials_v1_context.json" assert { type: "json" };
import jwsCtx from "./public/jws2020_v1_context.json" assert { type: "json" };
import trustframeworkCtx from "./public/trustframework_context.json" assert { type: "json" };

import myJson from "./public/myJson.json" assert {type: "json"};
import express from 'express';
import bodyParser from 'body-parser';

// Aquí monto el API REST para crear el JWS según la petición que reciba
const app = express();
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: false }));
const PORT = 3000;

app.listen(PORT, () => {
  console.log("Server Listening on PORT:", PORT);
});

app.post("/jws", async (request, response) => {
  let prueba = JSON.parse(request.body.json);
  console.log(await createJWS(request.body.pem, prueba));
  response.send({ "JSW": await createJWS(pemPrivateKey, myJson) });
});


app.get("/jws", async (request, response) => {
  console.log(await createJWS(pemPrivateKey, myJson));
  response.send({ "JSW": await createJWS(pemPrivateKey, myJson) });
});
// Definimos la clave privada para los get
const pemPrivateKey =
  "-----BEGIN PRIVATE KEY-----MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDRBL6jVcYoKb4gIp+qC27Hst/Mo7kCvYhDKkN5QNMtYL2rsydRwqfM8nEjeCJ7dhZR4Q7PfGEkQ8K5YAhByxE5VjWYYQNVyX4VrUSUEn0IGm5DjEkGmrUPgLOyL3A0Jv/SSovYKxMx6bNODfvg8MABb7+AtrY3GV+EPCk+T5iDax7uHfxKfpnjz4D8fGMy5bVHW+b1Fu/81j3/TmeJPmWfqAocajmlRqrYi7ObxIv2smtk55TaepnvwEatkIExmcyUprUK2T9IudLyBvtyc2/lYdzOqqkKr7XEhmbmoOvPi57L0oxeRpAz7Ydwmod+rUCDKSZbjFYF/9cMHNx2PggtAgMBAAECggEBALEpEFxoyzgniVq7fhEm95KT7lUJQDsuYlxrah1P8K45nQn3I5CNKKTxqSujG7cBdBGabG84wS13sYhl+RmrAMJUa8DoGWeRDSlaXxISSZ+gp2zhbtQGNQka0TRqOPQ7SgH35WgnunFH4A58k80owdV13h8+vlsdSnROebayyFY532SnWahi4e6bvU3mkwe+gBA65bbVIm2JdDtZJLhUyMFsMsm0Y8YMw8jpYAQtSkiNc7p/wLCNAp2dOcJ4Y8qsjZxDIv+5d+23h6Zr8PmLfL+gtV+sos1hASaMJHetlAibBx+jP1Xdxma9WJYYXXj7MUP2bmMam0pRv4dvCNZJRBECgYEA/ohrXhEaVL+RlNQkSvJFHvAJke/nxg4ZfNBQArufw72Jb8ec4bTa9dJDa9AHHx5xLUbV1YatcyqtmcETZMx5AHOo4nv/oucEu71U71XUE1pe2VZAaOFdAj4ZUWIFvCtjlXTyXG2OngdHUiOjlNh5qaas92kIq4kAlrFiD1L/1esCgYEA0jkqboRTUW42PFcTfuKV+Eob3hwVz3++YxvMDH6/+bHyHpJXHb+j+q5KAk8d3PkuGzieDl+ElCEw38R+jou6d1ONzKVRzjIJynjxIgrB4PZP9F7pLeIvZ+1gerlpYJyViehjBY3i0svn95pZKzypMOwec5chQGS2y5W1UzSsHEcCgYBRlE29R4QF96RkbB35u261/L9Ee/zwOKKoo2eRiKsrJHuBTRwWJ04qjaq4SmON8MbbeSGeH11GVT5w0jYyD2sU3v0ZIh8MCjk1JvirAPpI/aT6ya85LkoOJvMcZ2tpJQr04xeu0hpswe51ACE02rEb0+UKIyr5N57trYq9WJ/Q4wKBgDa6BQ7SSfJn85yPupaMnCgP+uM+gnsLMWARq3QRRx7UsUg+JomrCyBGYSPqvsZ45ATYH2V0fkolvdhzCdNIEtnfmYmN/Bbmtd/MzlFjZYeP986RKrj0Kg0vIa+xNvqcqN1G7whSIJtp09CEkPQNjaobve2viUt/LIshRRwNGUUfAoGBAMkzlBSJto78fsXL9b8oAiUsrSFsO/VnoKbjdxqMn1kn6yv86zTaYPdX6YzGAiSwbwByMuFF+e9k40iftYUDtZ29mECTVsO5Qrdxe5/72Zes7T2/cdo9HcvObKDPNgfV7JYRhBM9xF1LeuUXkS8bmvgLi0xWVYjiSLzu9a+M1QH0-----END PRIVATE KEY-----"

//Funcion de normalización del payload
async function normalize(payload) {
  return await jsonld.canonize(payload, {
    algorithm: 'URDNA2015',
    format: 'application/n-quads',
    documentLoader: staticDocumentLoader
  })

}
//Función intermedia para el hasheo del payload
function hash(payload) {
  return computePayloadHash(payload)
}
// Funcion de hasheo del payload
async function computePayloadHash(payload) {
  const encoder = new TextEncoder()
  const data = encoder.encode(payload)
  const digestBuffer = await crypto.subtle.digest('SHA-256', data)
  const digestArray = new Uint8Array(digestBuffer)
  return Array.from(digestArray)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}
// Constantes de contexto
const CACHED_CONTEXTS = {
  "https://www.w3.org/2018/credentials/v1": vcCtx,
  "https://w3id.org/security/suites/jws-2020/v1": jwsCtx,
  "https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#": trustframeworkCtx
}
//Carga estatica de documentos
const staticDocumentLoader = async url => {
  if (url in CACHED_CONTEXTS) {
    return {
      contextUrl: undefined,
      document: CACHED_CONTEXTS[url],
      documentUrl: url
    }
  }
  const document = await (await fetch(url)).json()
  return {
    contextUrl: undefined,
    document,
    documentUrl: url
  }
}
// Función asincrona para la creación del JWS al con los parametros pasados
async function createJWS(pem, json) {
  const rsaPrivateKey = await importPKCS8(pem, 'PS256')

  const credentialNormalized = await normalize(json)
  const credentialHashed = await hash(credentialNormalized)
  const credentialEncoded = new TextEncoder().encode(credentialHashed)

  return await new CompactSign(credentialEncoded).setProtectedHeader({
    alg: 'PS256',
    b64: false, crit: ['b64']
  }).sign(rsaPrivateKey);
}

console.log()