const express=require('express')
const axios=require('axios')
const crypto=require('crypto')
const moment=require('moment-timezone')

const app=express()
const port=5551
const hospitalUrl="http://localhost:5550"
const traUrl="http://localhost:6000"
const entityId="proxyserver1"
let sessionKey=null

app.use(express.json())

async function registerWithTra() {
    try {
        const response=await axios.post(`${traUrl}/register`, {
            entity_id:entityId,
            entity_type:"proxy_server"
        })
        sessionKey=response.data.session_key
        console.log("proxy server registered with tra. skey:", sessionKey)
    } catch (error) {
        console.error("tra registration failed. retrying...", error.message)
        setTimeout(registerWithTra, 5000)
    }
}

function generateHmac(nonce) {
    return crypto.createHmac('sha256', sessionKey)
                 .update(nonce)
                 .digest('hex')
}

function validateRequest(headers) {
    const entityid=headers["entity-id"]
    const nonce=headers["nonce"]
    const receivedHmac=headers["hmac"]

    if(!entityid||!nonce||!receivedHmac) {
        return false
    }

    const computedHmac=generateHmac(nonce)
    return crypto.timingSafeEqual(Buffer.from(receivedHmac), Buffer.from(computedHmac))
}

async function forwardRequest(req,res,endpoint) {
    try {
        if(!validateRequest(req.headers)) {
            return res.status(401).json({message:'authentication failed'})
        }

        print("forwarding a request to the original hospital server.")
        const response=await axios.post(`${hospitalUrl}${endpoint}`, req.body, {
            headers: {
                "entity-id":entityId,
                "nonce":crypto.randomBytes(16).toString('hex'),
                "hmac":generateHmac(crypto.randomBytes(16).toString('hex'))
            }
        })

        res.status(response.status).json(response.data)
    } catch (error) {
        console.error("error forwarding request:", error.message)
        res.status(500).json({message:'internal server error'})
    }
}

app.post('/data', (req,res) => {
    forwardRequest(req,res,'/data')
})

app.post('/error', (req,res) => {
    forwardRequest(req,res,'/error')
})

app.get('/data', async (req,res) => {
    try {
        const response=await axios.get(`${hospitalUrl}/data`)
        res.status(response.status).json(response.data)
    } catch (error) {
        console.error("error retrieving sensor data:", error.message)
        res.status(500).json({message:'internal server error'})
    }
})

app.get('/data/:id', async (req,res) => {
    try {
        const response=await axios.get(`${hospitalUrl}/data/${req.params.id}`)
        res.status(response.status).json(response.data)
    } catch (error) {
        console.error("error retrieving sensor data:", error.message)
        res.status(500).json({message:'internal server error'})
    }
})

app.get('/', async (req,res) => {
    try {
        const response=await axios.get(`${hospitalUrl}/`)
        res.send(response.data)
    } catch (error) {
        console.error("error serving web ui:", error.message)
        res.status(500).json({message:'internal server error'})
    }
})

app.get('/error-status', async (req,res) => {
    try {
        const response=await axios.get(`${hospitalUrl}/error-status`)
        res.status(response.status).json(response.data)
    } catch (error) {
        console.error("error retrieving intrusion status:", error.message)
        res.status(500).json({message:'internal server error'})
    }
})

registerWithTra()
app.listen(port, () => console.log(`proxy server running on port ${port}`))