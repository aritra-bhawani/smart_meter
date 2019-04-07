// Interfacing ACS712 With Arduino
const int sensorIn=A0;
int mVperAmp=185; // use 100 for 20A Module and 66 for 30A Module

float Voltage=0;
float VRMS=0;
float AmpsRMS=0;
float Energy=0;

void setup(){   
  Serial.begin(9600); 
}

void loop(){
uint32_t start_time = millis();
    while((millis()-start_time) < 5000){ //finding energy consumption in 5 sec at a sampling rate of 1 sec
      Voltage = getVPP();
      VRMS = (Voltage/2.0) *0.707; 
      AmpsRMS = (VRMS * 1000)/mVperAmp;
      Energy=Energy+(VRMS*AmpsRMS)*0.00028; // = 1/(60*60) equivalent reading on hourly basis
    }
    Serial.println(Energy); // value in W-Hr
    Energy=0;
}

float getVPP(){
  float result;
  int readValue;
  int maxValue = 0;
  int minValue = 1024;
  
   uint32_t start_time = millis();
   while((millis()-start_time) < 1000){ //Sampling of 1 sec
       readValue = analogRead(sensorIn);
       if (readValue > maxValue)
           maxValue = readValue;
       if (readValue < minValue) 
           minValue = readValue;
   }
   result = ((maxValue - minValue) * 5.0)/1024.0;
   return result;
 }
