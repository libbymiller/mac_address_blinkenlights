#include <ArduinoJson.h>
#include <Arduino.h>

extern "C" {
  #include <user_interface.h>
}

//based on https://github.com/jarkman/mac_address_blinkenlights/blob/master/mac_address_ropelights.lua#L116
// and https://github.com/kalanda/esp8266-sniffer
//it's crashy, something to do with delay etc
//neopixels stuff
#include <Wire.h>
#include <Adafruit_NeoPixel.h>
const int numPixels = 50;

// on a  wemos pin 2 is next to g and 5v
const int ledPin =  2;      // the number of the LED pin

Adafruit_NeoPixel strip = Adafruit_NeoPixel(numPixels, ledPin, NEO_GRB + NEO_KHZ800);


#define DATA_LENGTH           112

#define TYPE_MANAGEMENT       0x00
#define TYPE_CONTROL          0x01
#define TYPE_DATA             0x02
#define SUBTYPE_PROBE_REQUEST 0x04

struct RxControl {
 signed rssi:8; // signal intensity of packet
 unsigned rate:4;
 unsigned is_group:1;
 unsigned:1;
 unsigned sig_mode:2; // 0:is 11n packet; 1:is not 11n packet;
 unsigned legacy_length:12; // if not 11n packet, shows length of packet.
 unsigned damatch0:1;
 unsigned damatch1:1;
 unsigned bssidmatch0:1;
 unsigned bssidmatch1:1;
 unsigned MCS:7; // if is 11n packet, shows the modulation and code used (range from 0 to 76)
 unsigned CWB:1; // if is 11n packet, shows if is HT40 packet or not
 unsigned HT_length:16;// if is 11n packet, shows length of packet.
 unsigned Smoothing:1;
 unsigned Not_Sounding:1;
 unsigned:1;
 unsigned Aggregation:1;
 unsigned STBC:2;
 unsigned FEC_CODING:1; // if is 11n packet, shows if is LDPC packet or not.
 unsigned SGI:1;
 unsigned rxend_state:8;
 unsigned ampdu_cnt:8;
 unsigned channel:4; //which channel this packet in.
 unsigned:12;
};

struct SnifferPacket{
    struct RxControl rx_ctrl;
    uint8_t data[DATA_LENGTH];
    uint16_t cnt;
    uint16_t len;
};

// Declare each custom function (excluding built-in, such as setup and loop) before it will be called.
// https://docs.platformio.org/en/latest/faq.html#convert-arduino-file-to-c-manually
static void showMetadata(SnifferPacket *snifferPacket);
static void ICACHE_FLASH_ATTR sniffer_callback(uint8_t *buffer, uint16_t length);
static void printDataSpan(uint16_t start, uint16_t size, uint8_t* data);
static void getMAC(char *addr, uint8_t* data, uint16_t offset);
void channelHop();
void handleProbe(String mac);
void colorWipe6(int c[6], int wait);

static void showMetadata(SnifferPacket *snifferPacket) {

  unsigned int frameControl = ((unsigned int)snifferPacket->data[1] << 8) + snifferPacket->data[0];

  uint8_t version      = (frameControl & 0b0000000000000011) >> 0;
  uint8_t frameType    = (frameControl & 0b0000000000001100) >> 2;
  uint8_t frameSubType = (frameControl & 0b0000000011110000) >> 4;
  uint8_t toDS         = (frameControl & 0b0000000100000000) >> 8;
  uint8_t fromDS       = (frameControl & 0b0000001000000000) >> 9;

  // Only look for probe request packets
  if (frameType != TYPE_MANAGEMENT ||
      frameSubType != SUBTYPE_PROBE_REQUEST)
        return;

  char addr[] = "00:00:00:00:00:00";
  getMAC(addr, snifferPacket->data, 10);
  //Serial.print(" Peer MAC: ");
  //Serial.print(addr);
  handleProbe(addr);
}

/**
 * Callback for promiscuous mode
 */
static void ICACHE_FLASH_ATTR sniffer_callback(uint8_t *buffer, uint16_t length) {
  struct SnifferPacket *snifferPacket = (struct SnifferPacket*) buffer;
  showMetadata(snifferPacket);
}

static void printDataSpan(uint16_t start, uint16_t size, uint8_t* data) {
  for(uint16_t i = start; i < DATA_LENGTH && i < start+size; i++) {
    Serial.write(data[i]);
  }
}

static void getMAC(char *addr, uint8_t* data, uint16_t offset) {
  sprintf(addr, "%02x:%02x:%02x:%02x:%02x:%02x", data[offset+0], data[offset+1], data[offset+2], data[offset+3], data[offset+4], data[offset+5]);
}

#define CHANNEL_HOP_INTERVAL_MS   1000
static os_timer_t channelHop_timer;

/**
 * Callback for channel hoping
 */
void channelHop()
{
  // hoping channels 1-13
  uint8 new_channel = wifi_get_channel() + 1;
  if (new_channel > 13) {
    new_channel = 1;
  }
  wifi_set_channel(new_channel);
}

#define DISABLE 0
#define ENABLE  1

//pixels stuff
// from https://github.com/jarkman/mac_address_blinkenlights/blob/master/mac_address_ropelights.lua
int i = 0;
DynamicJsonDocument probes(1024);
String bestMac="00:00:00:00:00:00"; //-- MAC we're currently showing
//macPixels=ws2812.newBuffer(16,3)  -- pixel RGBs we've made from the current MAC
int macPixels[16];


//https://forum.arduino.cc/index.php?topic=311875.0
int strToHex(char str[])
{
  return (int) strtol(str, 0, 16);
}


//  make up 8 pixels form a mac
void makeMacPixels(){
    Serial.print("makeMacPixels: best Mac:");
    Serial.print(bestMac);
    Serial.print("\n");
    char m0[3], m1[3], m2[3], m3[3], m4[3], m5[3];
    bestMac.substring(0, 2).toCharArray(m0, 3);
    bestMac.substring(3, 5).toCharArray(m1, 3);
    bestMac.substring(6, 8).toCharArray(m2, 3);
    bestMac.substring(9, 11).toCharArray(m3, 3);
    bestMac.substring(12, 14).toCharArray(m4, 3);
    bestMac.substring(15, 17).toCharArray(m5, 3);    
     
    int rgbs[] = {strToHex(m0),strToHex(m1),strToHex(m2),strToHex(m3),strToHex(m4),strToHex(m5)};
    Serial.print("m0 "+String(m0)+" m1 "+m1+" m2 "+m2+" m3 "+m3+" m4 "+m4+" m5 "+m5);
    Serial.print("\n");
    Serial.print("rgbs0 "+String(rgbs[0])+" rgbs1 "+String(rgbs[1])+" rgbs2 "+String(rgbs[2])+" rgbs3 "+String(rgbs[3])+" rgbs4 "+String(rgbs[4])+" rgbs5 "+String(rgbs[5]));
    Serial.print("\n");
    colorWipe6(rgbs, 50);

}

//-- if this never gets called, reboot your ESP

void handleProbe(String mac){

    float foo = millis();
    float now = foo/10000;

    bool newMac = false;

    if(probes.isNull() || probes[mac]==NULL) {
        Serial.print("\nNew probe from "+mac);
        DynamicJsonDocument doc(1024);
        doc["frame"] = 0;
        doc["time"] = 0;
        probes[mac] = doc;
        serializeJson(probes, Serial);
        
        newMac = true; 
    }else{
        //Serial.print("got mac already!...here's the doc\n");
        //serializeJson(probes, Serial);
        float t = probes[mac]["time"];
        Serial.print("t is "+String(t)+"\n");
        Serial.print("now is "+String(now)+"\n");
        float age = now - t;
        Serial.print("age is "+String(age)+"\n");

        if(age > 1){  // -- many clients probe several times in a row, ignore repeats
           Serial.print("\nOld Probe from "+mac+" age : "+age+"\n");
           newMac = true;
        }else{
           Serial.print("\n\nage is < 5\n");
        }          
    }
    
    if (newMac){  
        //-- showFrame(probes[mac].frame)  
        Serial.print("\n\n\n!!!newmac bestMac: "+mac +"\n");
        
        bestMac = mac;
       
        probes[mac]["time"] = now;
        int zzz = probes[mac]["frame"];
        probes[mac]["frame"] = zzz+1; 
        makeMacPixels();
    }
}



void setup() {
  delay(1000);

  Serial.begin(115200);
  Serial.print("\nhello[0]\n");
  strip.begin();           // INITIALIZE NeoPixel strip object (REQUIRED)
  strip.show();            // Turn OFF all pixels ASAP
  strip.setBrightness(50); // Set BRIGHTNESS to about 1/5 (max = 255)
  makeMacPixels();
  // set the WiFi chip to "promiscuous" mode aka monitor mode

  delay(10);
  wifi_set_opmode(STATION_MODE);
  wifi_set_channel(1);
  wifi_promiscuous_enable(DISABLE);
  delay(10);
  wifi_set_promiscuous_rx_cb(sniffer_callback);
  delay(10);
  wifi_promiscuous_enable(ENABLE);

  //setup the channel hoping callback timer
  os_timer_disarm(&channelHop_timer);
  os_timer_setfn(&channelHop_timer, (os_timer_func_t *) channelHop, NULL);
  os_timer_arm(&channelHop_timer, CHANNEL_HOP_INTERVAL_MS, 1);

}

#define LED_COUNT 50
unsigned long time2 = millis();

void colorWipe6(int rgbs[6], int wait) {
    Serial.print("colorWipe6\n");
    //Serial.print("i "+String(i)+"\n");
    uint32_t c1 = strip.Color(rgbs[0],   rgbs[1],   rgbs[2]);
    uint32_t c2 = strip.Color(rgbs[3],   rgbs[4],   rgbs[5]);
    uint16_t j;
    for (j = 0;j < strip.numPixels();){

     if(millis()-time2 > 35){

      for (int i = 13; i > 7; i--){
        if(i+j < numPixels && i+j > -1){
          strip.setPixelColor(i+j, c1);
        }
      }

      for (int i = 7; i > 1; i--){
        if(i+j < numPixels && i+j > -1){
          strip.setPixelColor(i+j, c2);
        }
      }
      for (int i = 1; i > 0; i--){
        if(i+j < numPixels && i+j > -1){
          strip.setPixelColor(i+j, 0);
        }
      }     
      
      j++;
      time2 = millis();
      strip.show();
            
     }

   }
  
} 

void loop() {
  delay(10);  
}
