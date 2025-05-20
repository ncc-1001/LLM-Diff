When performing a diff analysis on two different versions of a binary, you need to do the following:
1. Use IDA to export the decompiled source code of the binary
2. Use the ida export_cd.py file to export the CG diagram of the binary
3. Use IDA to export the functional similarity of the two files, first execute the export_sim.py
Run the following command on the two exported .export files:
bindiff file_path1 ".export" file_path2   ".export" --output_format log --output_dir xxx
4. Filter out files with similar values of 1 (identical functions) based on the results of bindiff.
5. Perform LLM_Bindiff_CVEandFun.py auxiliary analysis of the remaining files using large models.
6. Please note that the api_key in QwnBot is a virtual value, please replace the api_key, base_url, and model in the actual application
