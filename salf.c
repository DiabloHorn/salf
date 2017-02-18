/*
Copyright (c) <2009> <DiabloHorn>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
/*
	SALF - Scriptable Anti Live Forensics
	Author: DiabloHorn
	Version: 0.1
	Comments: Run at your own risk!
	License: MIT License
	Todo: Fix security coding errors,tidy code up
	Purpose: defeat http://www.youtube.com/watch?v=-G8sEYCOv-o & http://www.youtube.com/watch?v=erq4TO_a3z8
	This will lock the computer when one of the several modules says it has to be locked.
	If your computer is full disk encrypted then a simple lock(assuming you have a strong password)
	is almost as good as a physical harddisk destruction. Cold Boot attack can defeat this, but then again...
	the inet says there is a anti-cold boot method out there...
*/

#include "salf.h"
/* 
	WARNING DIRTY CODE
	The code you are about to see will probably not be bug free and probably contains a lot of
	ugly code. I'm abusing the definition of POC to the fullest extent of it's meaning and grant myself the right
	to produce ugly code. Who knows, maybe in a later alpha/beta/final version it will be cleaned up.

*/
char inifile[MAX_PATH] = {0};
char pluginpath[MAX_PATH] = {0};
char dll_filter[MAX_PATH] = {0};
char py_filter[MAX_PATH] = {0};
int refreshping = 0;

int main(int argc,char *argv[]){
	int y,z,b;
	int aDLLPlugins = 0;
	int aPYPlugins = 0;
	char **DLLPlugins;
	char **PYPlugins;
	HANDLE *DLLPluginsLoaded = {0};
	BMyIsScrewed MyIsScrewed;
	

	printf("\tStarting SALF - Scriptable Anti Live Forensics\n");
	printf("\tPOC by DiabloHorn - http://diablohorn.wordpress.com\n");
	//First let's see if we got arguments and if the ini is readable
	if(argc != 2){
		printf("[*] %s\n","Please provide a ini file configuration");
		exit(0);
	}

	strncpy(inifile,argv[1],MAX_PATH);
	if(!ReadConfig()){
		printf("[*] %s %s\n","Failed to read INI",inifile);
		exit(0);
	}
	printf("[*] pluginpath: %s\n",pluginpath);
	printf("[*] dll filter: %s\n",dll_filter);
	printf("[*] python filter: %s\n",py_filter);
	printf("[*] refreshping: %d\n",refreshping);

	//now we should be able to start loading plugins...so let's count them first.
	aDLLPlugins = CountPluginFiles(dll_filter);
	aPYPlugins = CountPluginFiles(py_filter);
	printf("[*] %s\n","Searching for plugins");
	if(aDLLPlugins == 0 && aPYPlugins == 0){
		printf("[*] %s\n","No kind of valid plugin found");
		exit(0);
	}	
	printf("[*] Starting to load plugins\n");
	//counting has happend, let's load them
	/*DONT FORGET TO FREE()*/
	if(aDLLPlugins > 0){
		printf("[*] dll_plugins: %i\n", aDLLPlugins);
		DLLPlugins = (char **)malloc(aDLLPlugins*sizeof(char *));
		DLLPluginsLoaded = (HANDLE)malloc(aDLLPlugins*sizeof(HANDLE));
		for(z = 0; z < aDLLPlugins; z++){
			DLLPlugins[z] = malloc(MAX_PATH);
			DLLPluginsLoaded[z] = malloc(sizeof(HANDLE));
		}
		
		if(!LoadPluginFiles(DLLPlugins,dll_filter)){
			printf("[*] Loading dll plugin names failed\n");
			exit(0);//not sure if we should exit or continue with py_loading.
		}

		for(y=0;y<aDLLPlugins;y++){
			DLLPluginsLoaded[y] = LoadLibrary(DLLPlugins[y]);
		}
	}
	/*DONT FORGET TO FREE()*/
	if(aPYPlugins > 0){
		printf("[*] py_plugins: %i\n", aPYPlugins);
		PYPlugins = (char **)malloc(aPYPlugins*sizeof(char *));
		for(z = 0; z < aPYPlugins; z++){
			PYPlugins[z] = malloc(MAX_PATH);
		}

		if(!LoadPluginFiles(PYPlugins,py_filter)){
			printf("[*] Loading python plugin names failed\n");
		}
	}

	/*
		Main SALF loop.
		Loop through every loaded plugin and call it's "IsScrewed" function.
	*/
	while(1){
		printf("[*] Running DLL plugins\n");
		for(y=0;y<aDLLPlugins;y++){
			MyIsScrewed = (BMyIsScrewed) GetProcAddress(DLLPluginsLoaded[y],"IsScrewed");
			if(MyIsScrewed != NULL){
				if(MyIsScrewed()){
					printf("[**] ALERT!!!\n");
				}
			}
		}
		
		printf("[*] Running Python plugins\n");
		for(b=0;b<aPYPlugins;b++){
			if(CreateRunObject(PYPlugins[b])){
				printf("[**] ALERT!!!\n");
			}
		}
		printf("[*] Sleeping: %i seconds\n",refreshping/1000);
		Sleep(refreshping);
	}
	return 0;
}

/*
	Code modified from the original code @ http://docs.python.org/extending/embedding.html
*/
int CreateRunObject(char *pypname){
    PyObject *pName, *pModule, *pFunc;
	PyObject *pValue;
	char pyPath[MAX_PATH] = {0};
	char *tvar = (char *)malloc(MAX_PATH);
	char *tokstr = (char *)malloc(MAX_PATH);
	int i = 0;
	int pyRes = 1;//initialise to true
	Py_Initialize();
	pypname = strrchr(pypname,'\\');
	pypname++;
	while(pypname[i] != '\0'){
		if(pypname[i] == '.'){
			pypname[i] = '\0';
			break;
		}
		i++;
	}
    pName = PyString_FromString(pypname);
    /* Error checking of pName left out */
	PyRun_SimpleString("import sys");
	strcat(pyPath,"sys.path.append(\"");
	//double the slashes
	//remove trailing slashes
	tvar = strdup(pluginpath);
	tokstr = strtok(tvar,"\\");
	while(tokstr != NULL){
		strcat(pyPath,tokstr);
		strcat(pyPath,"\\\\");
		tokstr = strtok(NULL,"\\");
	}
	free(tvar);
	free(tokstr);
	pyPath[strlen(pyPath)-2] = '\0';
	strcat(pyPath,"\")");
	PyRun_SimpleString(pyPath);
    pModule = PyImport_Import(pName);
    Py_DECREF(pName);

    if (pModule != NULL) {
        pFunc = PyObject_GetAttrString(pModule, "IsScrewed");
        /* pFunc is a new reference */

        if (pFunc && PyCallable_Check(pFunc)) {
            pValue = PyObject_CallObject(pFunc,NULL);
            if (pValue != NULL) {
                pyRes = PyInt_AsLong(pValue);
                Py_DECREF(pValue);
            }
            else {
                Py_DECREF(pFunc);
                Py_DECREF(pModule);
                PyErr_Print();
				printf("[**] Python: Call failed\n");
            }
        }
        else {
            if (PyErr_Occurred())
                PyErr_Print();
            printf("[**] Python: Cannot find function \"%s\"\n", "IsScrewed");
        }
        Py_XDECREF(pFunc);
        Py_DECREF(pModule);
    }
    else {
        PyErr_Print();
        printf("[**] Python: Failed to load \"%s\"\n", pypname);
    }
    Py_Finalize();
    return pyRes;

}
/*
	Load the plugins based on the filter given
*/
int LoadPluginFiles(char **ToLoad,char *filter){
	WIN32_FIND_DATA ffd;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	int i;
	char FullPath[MAX_PATH] = {0};
	char FilterPath[MAX_PATH] = {0};
	strcat(FilterPath,pluginpath);
	strcat(FilterPath,filter);
	hFind = FindFirstFile(FilterPath, &ffd);
	
	if (INVALID_HANDLE_VALUE == hFind) 
	{
		printf("[*] Error\n");
		return 0;
	} 
	i = 0;
	do{
		strcat(FullPath,pluginpath);
		strcat(FullPath,ffd.cFileName);
		strcpy(ToLoad[i],FullPath);
		printf("[*] Found: %s\n",ToLoad[i]);
		i++;
		memset(&FullPath,0,MAX_PATH);
	}while(FindNextFile(hFind,&ffd) != 0);
	FindClose(hFind);
	return 1;
}

/*
	Loop through the plugins directory to find all plugins
	depending on the filter given
*/
int CountPluginFiles(char *filter){
	WIN32_FIND_DATA ffd;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	char sFiles[MAX_PATH] = {0};
	int i=0;
	/*prone to overflow*/
	strcat(sFiles,pluginpath);
	strcat(sFiles,filter);
	hFind = FindFirstFile(sFiles, &ffd);
	
	if (INVALID_HANDLE_VALUE == hFind) 
	{
		return i;
	} 

	do{
		i++;
	}while(FindNextFile(hFind,&ffd) != 0);
	FindClose(hFind);
	return i;
}


/*
	Read configuration from a ini file
*/
int ReadConfig(){
	
	GetPrivateProfileString(INI_SECTION,PLUGINPATH,"ERROR",pluginpath,MAX_PATH,inifile);
	GetPrivateProfileString(INI_SECTION,DLL_FILTER,"ERROR",dll_filter,MAX_PATH,inifile);
	GetPrivateProfileString(INI_SECTION,PY_FILTER,"ERROR",py_filter,MAX_PATH,inifile);
	refreshping = GetPrivateProfileInt(INI_SECTION,REFRESHPING,15000,inifile);
	if(strcmp("ERROR",pluginpath) == 0 || strcmp("ERROR",dll_filter) == 0 || strcmp("ERROR",py_filter) == 0){
		
		return 0;
	}
	return 1;
}

