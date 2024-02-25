
CXX = cl
CXXFLAGS = /EHsc /W4
LDFLAGS = /link /LIBPATH:"C:\Workspace\C\report-packet-stat" wpcap.lib

SOURCES = packet-stat.cpp
OBJECTS = $(SOURCES:.cpp=.obj)
EXECUTABLE = packet-stat.exe

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CXX) $(CXXFLAGS) /Fe$@ $** $(LDFLAGS)

{.}.cpp{.}.obj:
	$(CXX) $(CXXFLAGS) /Fo$@ /c $<

clean:
	del $(OBJECTS) $(EXECUTABLE)

