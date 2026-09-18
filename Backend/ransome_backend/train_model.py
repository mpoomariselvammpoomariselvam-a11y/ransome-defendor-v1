import os, joblib, pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

DATA='data/data_file.csv'
OUT='model/ransomware_model.joblib'
df=pd.read_csv(DATA)
# Target: Benign=1 means benign, 0 means ransomware in this dataset.
features=['Machine','DebugSize','DebugRVA','MajorImageVersion','MajorOSVersion','ExportRVA','ExportSize','IatVRA','MajorLinkerVersion','MinorLinkerVersion','NumberOfSections','SizeOfStackReserve','DllCharacteristics','ResourceSize','BitcoinAddresses']
X=df[features].apply(pd.to_numeric, errors='coerce').fillna(0)
y=(df['Benign'].astype(int)==0).astype(int) # 1 = ransomware, 0 = benign
Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=.2,random_state=42,stratify=y)
model=RandomForestClassifier(n_estimators=250,random_state=42,n_jobs=-1,class_weight='balanced')
model.fit(Xtr,ytr)
pred=model.predict(Xte)
print('Accuracy:', accuracy_score(yte,pred))
print(classification_report(yte,pred,target_names=['Benign','Ransomware']))
os.makedirs('model',exist_ok=True)
joblib.dump({'model':model,'features':features},OUT)
print('Saved',OUT)
