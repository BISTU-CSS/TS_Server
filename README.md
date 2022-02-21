# TimeStamp_Server

### 1.install gflags
git clone git@github.com:BISTUCSS/gflags.git --recursive

export CXXFLAGS="-fPIC" && cmake . && make VERBOSE=1

make && make install

### 2.install glog
git clone git@github.com:BISTUCSS/glog.git --recursive

cmake .

make -j4 

sudo make install

### 3.install googletest
git clone git@github.com:BISTUCSS/googletest.git --recursive

cmake .

make -j4

sudo make install