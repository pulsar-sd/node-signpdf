"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
var _exportNames = {
  SignPdf: true,
  SignPdfError: true
};
exports.SignPdf = void 0;
Object.defineProperty(exports, "SignPdfError", {
  enumerable: true,
  get: function () {
    return _SignPdfError.default;
  }
});
exports.default = void 0;

var axios = require('axios')
var _nodeForge = _interopRequireDefault(require("node-forge"));

var _SignPdfError = _interopRequireDefault(require("./SignPdfError"));

var _helpers = require("./helpers");

Object.keys(_helpers).forEach(function (key) {
  if (key === "default" || key === "__esModule") return;
  if (Object.prototype.hasOwnProperty.call(_exportNames, key)) return;
  if (key in exports && exports[key] === _helpers[key]) return;
  Object.defineProperty(exports, key, {
    enumerable: true,
    get: function () {
      return _helpers[key];
    }
  });
});

var _const = require("./helpers/const");

Object.keys(_const).forEach(function (key) {
  if (key === "default" || key === "__esModule") return;
  if (Object.prototype.hasOwnProperty.call(_exportNames, key)) return;
  if (key in exports && exports[key] === _const[key]) return;
  Object.defineProperty(exports, key, {
    enumerable: true,
    get: function () {
      return _const[key];
    }
  });
});

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

class SignPdf {
  constructor() {
    this.byteRangePlaceholder = _const.DEFAULT_BYTE_RANGE_PLACEHOLDER;
    this.lastSignature = null;
  }

  async sign(pdfBuffer, p12Buffer, additionalOptions = {}) {
    const options = {
      asn1StrictParsing: false,
      passphrase: '',
      ...additionalOptions
    };

    if (!(pdfBuffer instanceof Buffer)) {
      throw new _SignPdfError.default('PDF expected as Buffer.', _SignPdfError.default.TYPE_INPUT);
    }

    if (!(p12Buffer instanceof Buffer)) {
      throw new _SignPdfError.default('p12 certificate expected as Buffer.', _SignPdfError.default.TYPE_INPUT);
    }

    let pdf = (0, _helpers.removeTrailingNewLine)(pdfBuffer); // Find the ByteRange placeholder.

    const {
      byteRangePlaceholder
    } = (0, _helpers.findByteRange)(pdf);

    if (!byteRangePlaceholder) {
      throw new _SignPdfError.default(`Could not find empty ByteRange placeholder: ${byteRangePlaceholder}`, _SignPdfError.default.TYPE_PARSE);
    }

    const byteRangePos = pdf.indexOf(byteRangePlaceholder); // Calculate the actual ByteRange that needs to replace the placeholder.

    const byteRangeEnd = byteRangePos + byteRangePlaceholder.length;
    const contentsTagPos = pdf.indexOf('/Contents ', byteRangeEnd);
    const placeholderPos = pdf.indexOf('<', contentsTagPos);
    const placeholderEnd = pdf.indexOf('>', placeholderPos);
    const placeholderLengthWithBrackets = placeholderEnd + 1 - placeholderPos;
    const placeholderLength = placeholderLengthWithBrackets - 2;
    const byteRange = [0, 0, 0, 0];
    byteRange[1] = placeholderPos;
    byteRange[2] = byteRange[1] + placeholderLengthWithBrackets;
    byteRange[3] = pdf.length - byteRange[2];
    let actualByteRange = `/ByteRange [${byteRange.join(' ')}]`;
    actualByteRange += ' '.repeat(byteRangePlaceholder.length - actualByteRange.length); // Replace the /ByteRange placeholder with the actual ByteRange

    pdf = Buffer.concat([pdf.slice(0, byteRangePos), Buffer.from(actualByteRange), pdf.slice(byteRangeEnd)]); // Remove the placeholder signature

    pdf = Buffer.concat([pdf.slice(0, byteRange[1]), pdf.slice(byteRange[2], byteRange[2] + byteRange[3])]); // Convert Buffer P12 to a forge implementation.

    const forgeCert = _nodeForge.default.util.createBuffer(p12Buffer.toString('binary'));

    const p12Asn1 = _nodeForge.default.asn1.fromDer(forgeCert);

    const p12 = _nodeForge.default.pkcs12.pkcs12FromAsn1(p12Asn1, options.asn1StrictParsing, options.passphrase); // Extract safe bags by type.
    // We will need all the certificates and the private key.


    const certBags = p12.getBags({
      bagType: _nodeForge.default.pki.oids.certBag
    })[_nodeForge.default.pki.oids.certBag];

    const keyBags = p12.getBags({
      bagType: _nodeForge.default.pki.oids.pkcs8ShroudedKeyBag
    })[_nodeForge.default.pki.oids.pkcs8ShroudedKeyBag];

    const privateKey = keyBags[0].key; // Here comes the actual PKCS#7 signing.

    const p7 = _nodeForge.default.pkcs7.createSignedData(); // Start off by setting the content.


    p7.content = _nodeForge.default.util.createBuffer(pdf.toString('binary')); // Then add all the certificates (-cacerts & -clcerts)
    // Keep track of the last found client certificate.
    // This will be the public key that will be bundled in the signature.

    let certificate;
    Object.keys(certBags).forEach(i => {
      const {
        publicKey
      } = certBags[i].cert;
      p7.addCertificate(certBags[i].cert); // Try to find the certificate that matches the private key.

      if (privateKey.n.compareTo(publicKey.n) === 0 && privateKey.e.compareTo(publicKey.e) === 0) {
        certificate = certBags[i].cert;
      }
    });

    if (typeof certificate === 'undefined') {
      throw new _SignPdfError.default('Failed to find a certificate that matches the private key.', _SignPdfError.default.TYPE_INPUT);
    } // Add a sha256 signer. That's what Adobe.PPKLite adbe.pkcs7.detached expects.
    // Note that the authenticatedAttributes order is relevant for correct
    // EU signature validation:
    // https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/validation


    let signer = {
      key: privateKey,
      certificate,
      digestAlgorithm: _nodeForge.default.pki.oids.sha256,
      authenticatedAttributes: [
          {
              type: _nodeForge.default.pki.oids.contentType,
              value: _nodeForge.default.pki.oids.data,
          }, {
              type: _nodeForge.default.pki.oids.messageDigest,
              // value will be auto-populated at signing time
          }, {
              type: _nodeForge.default.pki.oids.signingTime,
              // value can also be auto-populated at signing time
              // We may also support passing this as an option to sign().
              // Would be useful to match the creation time of the document for example.
              value: new Date(),
          },
      ],
  }
  if (options.tsa) {
    signer = {
      ...signer,
      unauthenticatedAttributes: [
        {
            type: _nodeForge.default.pki.oids.timeStampToken, // "1.2.840.113549.1.9.16.2.14"
            value: ""
        }
      ]
    }
  }

    p7.addSigner(signer)
    p7.sign({
      detached: true
    }); // Check if the PDF has a good enough placeholder to fit the signature.

    /**
     * TSA implementation
     *
     * @param {String} tsaUrl
     * @param {signature} Signature data
     * @returns {object} Token
     */
    const tsa = async({
      tsaUrl,
      signature
    }) => {
      // Message imprint
      // openssl ts -query -data input.data -no_nonce -sha256 -cert -out openssl.tsq (for debug)
      // fs.writeFileSync(__dirname + '/input.data', raw , {encoding: 'binary'});
      // Generate SHA256 hash from signature content for TSA
      const md = _nodeForge.default.md.sha256.create();
      md.update(signature);

      // Generate TSA request
      const asn1Req = _nodeForge.default.asn1.create(
          _nodeForge.default.asn1.Class.UNIVERSAL,
          _nodeForge.default.asn1.Type.SEQUENCE,
          true,
          [
              // Version
              {
                  composed: false,
                  constructed: false,
                  tagClass: _nodeForge.default.asn1.Class.UNIVERSAL,
                  type: _nodeForge.default.asn1.Type.INTEGER,
                  value: _nodeForge.default.asn1.integerToDer(0).data,
              },
              {
                  composed: true,
                  constructed: true,
                  tagClass: _nodeForge.default.asn1.Class.UNIVERSAL,
                  type: _nodeForge.default.asn1.Type.SEQUENCE,
                  value: [
                      {
                          composed: true,
                          constructed: true,
                          tagClass: _nodeForge.default.asn1.Class.UNIVERSAL,
                          type: _nodeForge.default.asn1.Type.SEQUENCE,
                          value: [
                              {
                                  composed: false,
                                  constructed: false,
                                  tagClass: _nodeForge.default.asn1.Class.UNIVERSAL,
                                  type: _nodeForge.default.asn1.Type.OID,
                                  value: _nodeForge.default.asn1.oidToDer(_nodeForge.default.oids.sha256).data,
                              }, {
                                  composed: false,
                                  constructed: false,
                                  tagClass: _nodeForge.default.asn1.Class.UNIVERSAL,
                                  type: _nodeForge.default.asn1.Type.NULL,
                                  value: ""
                              }
                          ]
                      }, {// Message imprint
                          composed: false,
                          constructed: false,
                          tagClass: _nodeForge.default.asn1.Class.UNIVERSAL,
                          type: _nodeForge.default.asn1.Type.OCTETSTRING,
                          value: md.digest().data,
                      }
                  ]
              }, {
                  composed: false,
                  constructed: false,
                  tagClass: _nodeForge.default.asn1.Class.UNIVERSAL,
                  type: _nodeForge.default.asn1.Type.BOOLEAN,
                  value: 1, // Get REQ certificates
              }
          ]
      );

      const tsr = _nodeForge.default.asn1.toDer(asn1Req).data;

      // For debug
      // fs.writeFileSync(__dirname + '/generated.tsq', tsr , {encoding: 'binary'});

      // Send to TSA
      // curl -H "Content-Type: application/timestamp-query" --data-binary '@generated.tsq' https://freetsa.org/tsr
      // TODO: Authentication
      const response = await axios({
          method: "post",
          url: tsaUrl,
          data: Buffer.from(tsr, 'binary'),
          headers: {
              "Content-Type": `application/timestamp-query`,
          },
          responseType: 'arraybuffer',
          responseEncoding: 'binary'
      });

      // Return token (it contains cert data)
      return _nodeForge.default.asn1.fromDer(response.data.toString('binary')).value[1];
    } // end TSA helper function

    if (options.tsa) {
      const token = await tsa({
          tsaUrl: options.tsa,
          signature: options.signature
      });

      const created = _nodeForge.default.asn1.create(
        _nodeForge.default.asn1.Class.UNIVERSAL,
        _nodeForge.default.asn1.Type.SET,
        true,
        [token]
    );

      p7.signerInfos[0].value[6].value[0].value[1] = created
  }

    const raw = _nodeForge.default.asn1.toDer(p7.toAsn1()).getBytes(); // placeholderLength represents the length of the HEXified symbols but we're
    // checking the actual lengths.


    if (raw.length * 2 > placeholderLength) {
      throw new _SignPdfError.default(`Signature exceeds placeholder length: ${raw.length * 2} > ${placeholderLength}`, _SignPdfError.default.TYPE_INPUT);
    }

    let signature = Buffer.from(raw, 'binary').toString('hex'); // Store the HEXified signature. At least useful in tests.

    this.lastSignature = signature; // Pad the signature with zeroes so the it is the same length as the placeholder

    signature += Buffer.from(String.fromCharCode(0).repeat(placeholderLength / 2 - raw.length)).toString('hex'); // Place it in the document.

    pdf = Buffer.concat([pdf.slice(0, byteRange[1]), Buffer.from(`<${signature}>`), pdf.slice(byteRange[1])]); // Magic. Done.

    return pdf;
  }

}

exports.SignPdf = SignPdf;

var _default = new SignPdf();

exports.default = _default;