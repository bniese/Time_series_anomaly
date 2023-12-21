#!/usr/bin/env python
# coding: utf-8


import pandas as pd
import os
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import numpy as np
from statsmodels.tsa.seasonal import STL
from statsmodels.tsa.seasonal import seasonal_decompose  as sd
import scipy.stats as st


# preprocessed Zeek data are saved in "/folder/folder/folder/file"+day.strftime("%Y%m%d")+".csv"
# stitches together 2 weeks worth of data
datetime.now()
day_range = pd.date_range(start = (datetime.now()- timedelta(days = 15)), end = (datetime.now()- timedelta(days = 1)), freq = "1D")
file_list = []
for day in day_range:
    file_list.append("/folder/folder/folder/file"+day.strftime("%Y%m%d")+".csv")


# initialized an empty data frame
# begintds: timestamp in 30 minute increments
# port: port number
# scrip: source ip
# sessions: number of sessions to find anomalies in
df_dic = {"begintds":[], "srcip":[], "port":[], "sessions": []}
df = pd.DataFrame(df_dic)
today_file = pd.read_csv(file_list[-1])
for i in range(len(file_list)):
    temp = pd.read_csv(file_list[i])
    df = df.append(temp, ignore_index = True)

# list of IPs in file
ip_list = pd.unique(today_file["srcip"])

# initialize list of anomalies
anomaly_list = []
timestamp_range = pd.date_range(start = (datetime.now().date()- timedelta(days = 15)), end = (datetime.now().date()), freq = "30min")
# iterates through IPs
for ip in ip_list:
    # create a time series 
    good = df[(df["srcip"] == ip)]
    good["begintds"] = pd.to_datetime(good["begintds"])
    
    # create an empty series
    time_dic = {}
    time_df = pd.DataFrame(time_dic)
    time_df["begintds"] = timestamp_range
    
    # this merge fills in time points that have zero sessions
    good = time_df.merge(good, how = "left", on = "begintds")
    good.fillna(0, inplace = True)
    good.set_index("begintds", inplace = True)
    good.index = pd.to_datetime(good.index)
    
    # this fits the data with seasonal decomposition to account for recurring daily processes 
    good_fit = sd(good["sessions"], period = 48)
    
    # need to get rid of the ends of the time series
    good_residual = good_fit.resid[-73:-24]
    
    # the values 10 is a user input to define what an anomaly looks like
    anomalies = good_residual[(good_residual > 10)]
    for anomaly in anomalies.index:
        anomaly_list.append([anomaly, ip, good["sessions"][anomaly], anomalies[anomaly], 443])



anomaly_df= pd.DataFrame(anomaly_list,columns=["begintds","srcip","sessions","residual", "port"])


# labels the data for adding to splunk
anomaly_df["type"] = "tcp_sessions_anomaly"



anomaly_df.to_csv("/opt/splunk_logs/tcp_session_anomalies/tcp_anomalies_"+str(datetime.now())[0:10] +".csv", index = False )

    


