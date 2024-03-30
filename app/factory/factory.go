package factory

import (
    "errors"
    "fmt"
    "math/rand"
    "net/url"
    "strconv"
    "strings"
    "time"

    "github.com/go-resty/resty/v2"
    "github.com/thank243/zteOnu/utils"
)

const (
	AesKeyPool = []byte{
		0x7B, 0x56, 0xB0, 0xF7, 0xDA, 0x0E, 0x68, 0x52, 0xC8, 0x19,
		0xF3, 0x2B, 0x84, 0x90, 0x79, 0xE5, 0x62, 0xF8, 0xEA, 0xD2,
		0x64, 0x93, 0x87, 0xDF, 0x73, 0xD7, 0xFB, 0xCC, 0xAA, 0xFE,
		0x75, 0x43, 0x1C, 0x29, 0xDF, 0x4C, 0x52, 0x2C, 0x6E, 0x7B,
		0x45, 0x3D, 0x1F, 0xF1, 0xDE, 0xBC, 0x27, 0x85, 0x8A, 0x45,
		0x91, 0xBE, 0x38, 0x13, 0xDE, 0x67, 0x32, 0x08, 0x54, 0x11,
		0x75, 0xF4, 0xD3, 0xB4, 0xA4, 0xB3, 0x12, 0x86, 0x67, 0x23,
		0x99, 0x4C, 0x61, 0x7F, 0xB1, 0xD2, 0x30, 0xDF, 0x47, 0xF1,
		0x76, 0x93, 0xA3, 0x8C, 0x95, 0xD3, 0x59, 0xBF, 0x87, 0x8E,
		0xF3, 0xB3, 0xE4, 0x76, 0x49, 0x88,
	}

	AesKeyPoolNew = []byte{
		0x8C, 0x23, 0x65, 0xD1, 0xFC, 0x32, 0x45, 0x37, 0x11, 0x28,
		0x71, 0x63, 0x07, 0x20, 0x69, 0x14, 0x73, 0xE7, 0xD4, 0x53,
		0x13, 0x24, 0x36, 0xC2, 0xB5, 0xE1, 0xFC, 0xCF, 0x8A, 0x9A,
		0x41, 0x89, 0x3C, 0x49, 0xCF, 0x5C, 0x72, 0x8C, 0x9E, 0xEB,
		0x75, 0x0D, 0x3F, 0xD1, 0xFE, 0xCC, 0x57, 0x65, 0x7A, 0x35,
		0x21, 0x3E, 0x68, 0x53, 0x7E, 0x97, 0x02, 0x48, 0x74, 0x71,
		0x95, 0x34, 0x53, 0x84, 0xB4, 0xC3, 0xE2, 0xD6, 0x27, 0x3D,
		0xE6, 0x5D, 0x72, 0x9C, 0xBC, 0x3D, 0x03, 0xFD, 0x76, 0xC1,
		0x9C, 0x25, 0xA8, 0x92, 0x47, 0xE4, 0x18, 0x0F, 0x24, 0x3F,
		0x4F, 0x67, 0xEC, 0x97, 0xF4, 0x99,
	}
)

type Factory struct {
    user   string
    passwd string
    ip     string
    port   int
    cli    *resty.Client
    Key    []byte
}

func NewFactory(user, passwd, ip string, port int) (*Factory, error) {
    if user == "" {
        return nil, errors.New("user cannot be empty")
    }
    if passwd == "" {
        return nil, errors.New("password cannot be empty")
    }
    if ip == "" {
        return nil, errors.New("ip cannot be empty")
    }
    if port <= 0 {
        return nil, errors.New("port must be a positive integer")
    }

    return &Factory{
        user:   user,
        passwd: passwd,
        ip:     ip,
        port:   port,
        cli:    resty.New().SetBaseURL(fmt.Sprintf("http://%s:%d", ip, port)),
    }, nil
}

func (f *Factory) Reset() error {
    resp, err := f.cli.R().SetBody("SendSq.gch").Post("webFac")
    if err != nil {
        return errors.Wrap(err, "failed to reset factory")
    }
    if resp.StatusCode() == 400 {
        return nil
    }

    return errors.New(resp.String())
}

func (f *Factory) ReqFactoryMode() error {
    _, err := f.cli.R().SetBody("RequestFactoryMode.gch").Post("webFac")
    if err != nil {
        if err.(*url.Error).Err.Error() != "EOF" {
            return errors.Wrap(err, "failed to request factory mode")
        }
    }
    return nil
}

func (f *Factory) SendSq() (uint8, error) {
    var (
        keyPool []byte
        idx     int
        version uint8
    )

    r := rand.New(rand.NewSource(time.Now().Unix())).Intn(60)
    resp, err := f.cli.R().SetBody(fmt.Sprintf("SendSq.gch?rand=%d", r)).Post("webFac")
    if err != nil {
        return 0, errors.Wrap(err, "failed to send sq")
    }
    if resp.StatusCode() != 200 {
        return 0, errors.New(resp.String())
    }

    if strings.Contains(resp.String(), "newrand") {
        keyPool = AesKeyPoolNew
        version = 2

        newRand, _ := strconv.Atoi(strings.ReplaceAll(resp.String(), "newrand=", ""))
        idx = ((0x1000193*r)&0x3F ^ newRand) % 60
    } else if len(resp.String()) == 0 {
        keyPool = AesKeyPool
        version = 1
    } else {
        return 0, errors.New("unknown error")
    }

    // Get keys
    pool := keyPool[idx : idx+24]
    f.Key = make([]byte, len(pool))
    for i := range pool {
        f.Key[i] = (pool[i] ^ 0xA5) & 0xFF
    }

    return version, nil
}

func (f *Factory) CheckLoginAuth() error {
    payload, err := utils.ECBEncrypt(
        []byte(fmt.Sprintf("CheckLoginAuth.gch?version50&user=%s&pass=%s", f.user, f.passwd)), f.Key)
    if err != nil {
        return errors.Wrap(err, "failed to encrypt payload")
    }

    resp, err := f.cli.R().SetBody(payload).Post("webFacEntry")
    if err != nil {
        return errors.Wrap(err, "failed to check login auth")
    }
    switch resp.StatusCode() {
    case 200:
        if _, err := utils.ECBDecrypt(resp.Body(), f.Key); err != nil {
            return errors.Wrap(err, "failed to decrypt response")
        }
        return nil
    case 400:
        return errors.New("unknown errors")
    case 401:
        return errors.New("errors user or password")
    default:
        return errors.New(resp.String())
    }
}

func (f *Factory) SendInfo() error {
    payload, err := utils.ECBEncrypt([]byte("SendInfo.gch?info=6|"), f.Key)
    if err != nil {
        return errors.Wrap(err, "failed to encrypt payload")
    }
    resp, err := f.cli.R().SetBody(payload).Post("webFacEntry")
    if err != nil {
        return errors.Wrap(err, "failed to send info")
    }

    switch resp.StatusCode() {
    case 200:
        return nil
    case 400:
        return errors.New("unknown errors")
    case 401:
        return errors.New("info error")
    default:
        return errors.New(resp.String())
    }
}

func (f *Factory) FactoryMode() (user string, pass string, err error) {
    payload, err := utils.ECBEncrypt([]byte("FactoryMode.gch?mode=2&user=notused"), f.Key)
    if err != nil {
        return "", "", errors.Wrap(err, "failed to encrypt payload")
    }
    resp, err := f.cli.R().SetBody(payload).Post("webFacEntry")
    if err != nil {
        return "", "", errors.Wrap(err, "failed to enter factory mode")
    }

    dec, err := utils.ECBDecrypt(resp.Body(), f.Key)
    if err != nil {
        return "", "", errors.Wrap(err, "failed to decrypt response")
    }

    u, err := url.Parse(string(dec))
    if err != nil {
        return "", "", errors.Wrap(err, "failed to parse response")
    }

    q := u.Query()
    user = q.Get("user")
    pass = q.Get("pass")

    return
}

func (f *Factory) Handle() (tlUser string, tlPass string, err error) {
    fmt.Println(strings.Repeat("-", 35))

    fmt.Print("step [0] reset factory: ")
    if err = f.Reset(); err != nil {
        return "", "", errors.Wrap(err, "failed to reset factory")
    } else {
        fmt.Println("ok")
    }

    fmt.Print("step [1] request factory mode: ")
    if err = f.ReqFactoryMode(); err != nil {
        return "", "", errors.Wrap(err, "failed to request factory mode")
    } else {
        fmt.Println("ok")
    }

    var ver uint8
    fmt.Print("step [2] send sq: ")
    ver, err = f.SendSq()
    if err != nil {
        return "", "", errors.Wrap(err, "failed to send sq")
    } else {
        fmt.Println("ok")
    }

    fmt.Print("step [3] check login auth: ")
    switch ver {
    case 1:
        if err = f.CheckLoginAuth(); err != nil {
            return "", "", errors.Wrap(err, "failed to check login auth")
        }
    case 2:
        if err = f.SendInfo(); err != nil {
            return "", "", errors.Wrap(err, "failed to send info")
        }
        if err = f.CheckLoginAuth(); err != nil {
            return "", "", errors.Wrap(err, "failed to check login auth")
        }
    }
    fmt.Println("ok")

    fmt.Print("step [4] enter factory mode: ")
    tlUser, tlPass, err = f.FactoryMode()
    if err != nil {
        return "", "", errors.Wrap(err, "failed to enter factory mode")
    } else {
        fmt.Println("ok")
    }

    fmt.Println(strings.Repeat("-", 35))

    return
}
