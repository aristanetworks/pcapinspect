#!/usr/bin/env python3
#
# Copyright (c) 2020 Arista Networks, Inc.  All rights reserved.
# Use of this source code is governed by the MIT license that can be found
# in the LICENSE file.

import argparse
import os
import json
import subprocess
from collections import defaultdict
from pprint import pprint

import matplotlib.pyplot as plt
import numpy as np

from OuiMap import ouiMap

openStr = 'Open'
updateStr = 'Update'
eorStr = 'EOR'
notificationStr = 'Notification'
keepaliveStr = 'Keepalive'
routeRefreshStr = 'Route-Refresh'

bgpMsgTypeMap = {
   '1' : openStr,
   '2' : updateStr,
   '3' : notificationStr,
   '4' : keepaliveStr,
   '5' : routeRefreshStr
}

class MinMax( object ):
   def __init__( self, val, ignoreFrames=None ):
      self.val = val
      self.frameNum = 0
      if ignoreFrames is None:
         ignoreFrames = []
      self.ignoreFrames = ignoreFrames

   def maybeUpdate( self, val, frameNum ):
      if frameNum in self.ignoreFrames:
         return
      if self.compare( val ):
         self.val = val
         self.frameNum = frameNum

class Min( MinMax ):
   def compare( self, val ):
       return val < self.val

class Max( MinMax ):
   def compare( self, val ):
       return val > self.val

class Plotter( object ):
   def plot( self, data, style ):
      fig, ax = plt.subplots( figsize=( 10, 6 ) )
      if 'xlim' in data:
         plt.xlim( data[ 'xlim' ] )
      if style == 'lines':
         ax.plot( data[ 'x' ], data[ 'y' ] )
      elif style == 'points':
         # TODO: What can I choose instead of 'bo'?
         ax.plot( data[ 'x' ], data[ 'y' ], 'bo' )
      else:
         assert style == 'boxes'
         plt.bar( data[ 'x' ], data[ 'y' ], width=data[ 'barwidth' ], figure=fig )
      ax.set_xlabel( data[ 'xlabel' ] )
      ax.set_ylabel( data[ 'ylabel' ] )
      ax.set_title( data[ 'title' ] )
      plt.savefig( data[ 'imageName' ] )

class FramePlugin( object ):
   def __init__( self, frames ):
      self.frames = frames

   def requiredPcapFields( self ):
      return [
         'frame.number',
         'frame.len',
         'frame.time_relative',
         'frame.time_delta'
      ]

   def processJsonFrame( self, jsonFrame, processedFrame ):
      frameNum = int( jsonFrame[ 'frame.number' ][ 0 ] )
      processedFrame[ 'frame.number' ] = frameNum
      processedFrame[ 'frame.len' ] = int( jsonFrame[ 'frame.len' ][ 0 ] )
      processedFrame[ 'frame.time_delta' ] = float(
         jsonFrame[ 'frame.time_delta' ][ 0 ] )
      frameTimeRelative = float( jsonFrame[ 'frame.time_relative' ][ 0 ] )
      processedFrame[ 'frame.time_relative' ] = frameTimeRelative

class EthernetPlugin( object ):
   def __init__( self, frames ):
      self.frames = frames

   def requiredPcapFields( self ):
      return [
         # sll = 'Source link-layer address' - PCAP was captured as 'Linux
         # cooked capture' on the special 'any' device.
         'sll.src.eth',
         'eth.src',
         'eth.dst'
      ]

   def processJsonFrame( self, jsonFrame, processedFrame ):
      if 'sll.src.eth' in jsonFrame:
         # sll = 'Source link-layer address' - PCAP was captured as 'Linux
         # cooked capture' on the special 'any' device.
         # Doesn't contain a destination address
         ethSrcStr = 'sll.src.eth'
      elif 'eth.src' in jsonFrame:
         ethSrcStr = 'eth.src'
         # Assume eth.dst is present
         processedFrame[ 'eth.dst' ] = jsonFrame[ 'eth.dst' ][ 0 ]
      else:
         return
      processedFrame[ ethSrcStr ] = jsonFrame[ ethSrcStr ][ 0 ]
      processedFrame[ 'ETH_SRC' ] = jsonFrame[ ethSrcStr ][ 0 ]

   def findUniqueSrcMacs( self ):
      srcMacs = defaultdict( set )
      for frame in self.frames.values():
         srcMac = frame[ 'ETH_SRC' ]
         ipsAtSrcMac = srcMacs[ srcMac ]
         # This is a slight abuse of the plugins' separation. 'IP_SRC' belongs to IpPlugin.
         if 'IP_SRC' in frame:
            ipsAtSrcMac.add( frame[ 'IP_SRC' ] )
      return srcMacs

class IpPlugin( object ):
   def __init__( self, frames ):
      self.frames = frames
      self.ipFrames = []
      self.ipV4Frames = []
      self.ipV6Frames = []
      self.framesPerIpSrc = defaultdict( list )
      self.framesPerIpDst = defaultdict( list )

   def requiredPcapFields( self ):
      return [
         'ip.src',
         'ip.dst',
         'ipv6.src',
         'ipv6.dst',
      ]
   def processJsonFrame( self, jsonFrame, processedFrame ):
      frameNum = processedFrame[ 'frame.number' ]
      if 'ip.src' in jsonFrame: # Is IPv4, not IPv6
         ipSrcStr = 'ip.src'
         ipDstStr = 'ip.dst'
         self.ipV4Frames.append( frameNum )
      elif 'ipv6.src' in jsonFrame:
         ipSrcStr = 'ipv6.src'
         ipDstStr = 'ipv6.dst'
         self.ipV6Frames.append( frameNum )
      else:
         return
      srcAddr = jsonFrame[ ipSrcStr ][ 0 ]
      dstAddr = jsonFrame[ ipDstStr ][ 0 ]
      processedFrame[ ipSrcStr ] = srcAddr
      processedFrame[ ipDstStr ] = dstAddr
      processedFrame[ 'IP_SRC' ] = srcAddr
      processedFrame[ 'IP_DST' ] = dstAddr
      self.ipFrames.append( frameNum )
      self.framesPerIpSrc[ srcAddr ].append( frameNum )
      self.framesPerIpDst[ dstAddr ].append( frameNum )

   def findUniqueSrcIpsWithMacs( self ):
      # frames is keyed on SRC_IP
      uniqueIps = {}
      for ip, frames in self.framesPerIpSrc.items():
         macAddrs = set()
         for frameNum in frames:
            macAddrs.add( self.frames[ frameNum ][ 'ETH_SRC' ] )
         uniqueIps[ ip ] = macAddrs
      return uniqueIps

class TcpPlugin( object ):
   def __init__( self, frames ):
      self.frames = frames
      self.tcpFrames = []

   def requiredPcapFields( self ):
      return [
         'tcp.len',
         'tcp.seq',
         'tcp.ack',
         'tcp.window_size'
      ]

   def processJsonFrame( self, jsonFrame, processedFrame ):
      if 'tcp.len' not in jsonFrame:
         return
      processedFrame[ 'tcp.ack' ] = int( jsonFrame[ 'tcp.ack' ][ 0 ] )
      processedFrame[ 'tcp.len' ] = int( jsonFrame[ 'tcp.len' ][ 0 ] )
      processedFrame[ 'tcp.seq' ] = int( jsonFrame[ 'tcp.seq' ][ 0 ] )
      processedFrame[ 'tcp.window_size' ] = int(
         jsonFrame[ 'tcp.window_size' ][ 0 ] )
      self.tcpFrames.append( processedFrame[ 'frame.number' ] )

class BgpPlugin( object ):
   def __init__( self, frames ):
      self.frames = frames
      self.bgpFrames = []
      self.eorFrameNums = {}

   def requiredPcapFields( self ):
      return [
         'bgp.type',
         'bgp.length',
         'bgp.update.nlri',
         'bgp.prefix_length',
         'bgp.nlri_prefix'
      ]

   def processJsonFrame( self, jsonFrame, processedFrame ):
      if 'bgp.type' not in jsonFrame:
         return
      bgpType = []
      bgpLen = []
      frameNum = processedFrame[ 'frame.number' ]
      ipSrc = processedFrame[ 'IP_SRC' ]
      bgpLen = [ int( l ) for l in jsonFrame[ 'bgp.length' ] ]
      i = 0
      for msgType in jsonFrame[ 'bgp.type' ]:
         msgType = bgpMsgTypeMap[ msgType ]
         # TODO: EOR check needs to be v4/v6 aware.
         if msgType == updateStr and bgpLen[ i ] == 23:
            self.eorFrameNums.setdefault( ipSrc, [] ).append( frameNum )
         # TODO: Change bgpType/'bgp.type' to something else such as bgpMsgTypes or
         # bgpMsgs?
         bgpType.append( msgType )
         i += 1
      processedFrame[ 'bgp.type' ] = bgpType
      processedFrame[ 'bgp.length' ] = bgpLen
      self.bgpFrames.append( frameNum )

   def findEor( self, ip, devName ):
      # TODO: Show all EORs if there's more than 1.
      if ip not in self.eorFrameNums:
         return None
      eorFrameNum = self.eorFrameNums[ ip ] [ 0 ]
      eorFrame = self.frames[ eorFrameNum ]
      eorFrameTime = eorFrame[ 'frame.time_relative' ]
      print( '%s EOR is in frame %u at %.6f' % (
         devName, eorFrameNum, eorFrameTime ) )
      return ( eorFrameNum, eorFrameTime )

class Plugin( object ):
   def __init__( self, frames ):
      self.frames = frames

   def requiredPcapFields( self ):
      return [
      ]

   def processJsonFrame( self, jsonFrame, processedFrame ):
      pass

class PcapInspect( object ):
   def __init__( self, pcapFilename, numTimeSlots=80, stopAnalysisTime=None,
                 keepJson=False, plugins=None ):
      self.pcapFilename = pcapFilename
      self.numTimeSlots = numTimeSlots
      # TODO: Handle data finishing before stopAnalysisTime.
      #       Make this an optional command-line argument.
      self.stopAnalysisTime = stopAnalysisTime
      self.keepJson = keepJson
      ( self.directory, filename ) = os.path.split( pcapFilename )
      if self.directory == '':
         self.directory = '.'
      self.directory += '/'
      ( self.baseFilename, _extension ) = os.path.splitext( filename )
      self.jsonFilename = self.directory + self.baseFilename + '.json'

      self.requiredPcapFields = []
      self.frames = {}

      if not plugins:
         plugins = [
            'FramePlugin',
            'EthernetPlugin',
            'IpPlugin',
            'TcpPlugin',
            'BgpPlugin'
         ]
      self.plugins = {}
      self.orderedPlugins = []
      globalVars = globals()
      for pluginName in plugins:
         pluginClass = globalVars[ pluginName ]
         pluginObj = pluginClass( self.frames )
         self.orderedPlugins.append( pluginObj )
         self.plugins[ pluginName ] = pluginObj
         self.requiredPcapFields.extend( pluginObj.requiredPcapFields() )

      self.processPcap()

   def generateJsonFramesFromPcap( self ):
      '''Use tshark to convert .pcap file to more readable JSON.'''
      requiredFieldsArgs = []
      for field in self.requiredPcapFields:
         requiredFieldsArgs.extend( [ '-e', field ] )

      cmdArgs = [ 'tshark', '-r', self.pcapFilename, '-T', 'json'
                ] + requiredFieldsArgs
      try:
         proc = subprocess.run( cmdArgs, capture_output=True, text=True )
      except subprocess.CalledProcessError as e:
         print( 'CalledProcessError: %s' % e.output )
         raise
      json = proc.stdout
      if self.keepJson:
         with open( self.jsonFilename, 'w' ) as f:
            f.write( json )
      return json

   def processJsonFrame( self, jsonFrame ):
      '''Removes the cruft from the frame info produced by json.loads() and
         returns a cleaned up dict.'''
      processedFrame = {}
      for plugin in self.orderedPlugins:
         plugin.processJsonFrame( jsonFrame, processedFrame )
      return processedFrame

   def processPcap( self ):
      jsonFrames = json.loads( self.generateJsonFramesFromPcap() )

      for jsonFrame in jsonFrames:
         processedFrame = self.processJsonFrame( jsonFrame[ '_source' ][ 'layers' ] )
         frameNum = processedFrame[ 'frame.number' ]
         self.frames[ frameNum ] = processedFrame

   # TODO: Make this a generator?
   def filterFrames( self, frameNumsIn, filterFunc ):
      frameNumsOut = [ fNum for fNum in frameNumsIn
                       if filterFunc( self.frames[ fNum ] ) ]
      return frameNumsOut

   def analyzeRemainingRxWindow( self, frameNums, ipA, ipB, scaleA=0, scaleB=0 ):
      '''scaleA & scaleB allow us to adjust scaling if the PCAP does not contain
      the 3-way TCP handshake which is where the peers exchange window scale values.
      If the PCAP does contain the handshake, then tshark will have adjusted the
      value of tcp.window_size already. Valid values are 0 to 14, but we don't assert
      on this to allow experimentation.
      See https://datatracker.ietf.org/doc/html/rfc1323#page-8'''
      # TODO: Don't need brackets for tuple when shape arg to np.empty is a scalar - fix this elsewhere.
      #remainingRxWindowA = np.empty( len( frameNums ), dtype=int )
      #remainingRxWindowB = np.empty( len( frameNums ), dtype=int )
      remainingRxWindowA = []
      remainingRxWindowB = []
      remainingA = 0
      remainingB = 0
      lastSetWindowA = -1
      lastSetWindowB = -1
      for frameNum in frameNums:
         # TODO: How should I handle retransmitted frames?
         frame = self.frames[ frameNum ]
         if frame[ 'IP_SRC' ] == ipA:
            assert frame[ 'IP_DST' ] == ipB
            remainingA = frame[ 'tcp.window_size' ] * ( 1 << scaleA )
            remainingB -= frame[ 'tcp.len' ]
            lastSetWindowA = frameNum
         else:
            assert frame[ 'IP_DST' ] == ipA
            assert frame[ 'IP_SRC' ] == ipB
            remainingA -= frame[ 'tcp.len' ]
            remainingB = frame[ 'tcp.window_size' ] * ( 1 << scaleB )
            lastSetWindowB = frameNum
         negativeLastSetWindowA = lastSetWindowA if lastSetWindowA > 0 \
                                                    and remainingA < 0 else None
         negativeLastSetWindowB = lastSetWindowB if lastSetWindowB > 0 \
                                                    and remainingB < 0 else None
         remainingRxWindowA.append(
            { 'frameNum' : frameNum,
              'remaining' : remainingA,
              'negativeLastSetWindow' : negativeLastSetWindowA } )
         remainingRxWindowB.append(
            { 'frameNum' : frameNum,
              'remaining' : remainingB,
              'negativeLastSetWindow' : negativeLastSetWindowB } )
      return remainingRxWindowA, remainingRxWindowB

   def genRemainingRxWindowPlotData( self, remainingRxWindow, rxDevName, txDevName ):
      timePlot = np.empty( ( len( remainingRxWindow ) ) )
      remainingRxWindowPlot = np.empty( len( remainingRxWindow ), dtype=int )
      i = 0
      for r in remainingRxWindow:
         frame = self.frames[ r[ 'frameNum' ] ]
         timePlot[ i ] = frame[ 'frame.time_relative' ]
         remainingRxWindowPlot[ i ] = r[ 'remaining' ]
         i += 1
         
      plotData = {
         'x': timePlot,
         'y': remainingRxWindowPlot,
         'title': 'Remaining unused Rx TCP Window - Rx: %s, Tx: %s (%s)' % (
            rxDevName, txDevName, self.pcapFilename ),
         'xlabel': 'Time (seconds)',
         'ylabel': 'Remaining unused RX TCP Window (bytes)',
         'imageName': self.directory + ( '%s_remaining_window_' % rxDevName ) + \
         self.baseFilename + '.png'
      }
      return plotData

   def genNegativeWindowDelayPlotData( self, remainingRxWindow, rxDevName, txDevName ):
      negativeWindow = [ r for r in remainingRxWindow
                         if r[ 'negativeLastSetWindow' ] is not None ]
      timePlot = np.empty( ( len( negativeWindow ) ) )
      negativeWindowDelayPlot = np.empty( len( negativeWindow ) )
      i = 0
      for n in negativeWindow:
         frame = self.frames[ n[ 'frameNum' ] ]
         frameTime = frame[ 'frame.time_relative' ]
         timePlot[ i ] = frameTime
         setWindowFrame = self.frames[ n[ 'negativeLastSetWindow' ] ]
         setWindowTime = setWindowFrame[ 'frame.time_relative' ]
         negativeWindowDelayPlot[ i ] = frameTime - setWindowTime
         i += 1

      firstFrame = self.frames[ remainingRxWindow[ 0 ][ 'frameNum' ] ]
      lastFrame = self.frames[ remainingRxWindow[ -1 ][ 'frameNum' ] ]
      # TODO: Does the imageName belong in the caller?
      plotData = {
         'x': timePlot,
         # Force the x-axis to be the same as the other plots (for visual comparison).
         # timePlot doesn't have a value for every frame. Without xlim, the auto-scaling
         # would make give this plot a different x-axis from the other plots.
         'xlim': ( firstFrame[ 'frame.time_relative' ],
                   lastFrame[ 'frame.time_relative' ] ),
         'y': negativeWindowDelayPlot,
         # TODO: This should be in a text box instead?
         'title': '%s Rx TCP Window is negative. '
                  'Elapsed time since window size was set when data RXed from %s (%s)' % (
                     rxDevName, txDevName, self.pcapFilename ),
         'xlabel': 'Time (seconds)',
         'ylabel': 'Delay since window size was set (seconds)',
         'imageName': self.directory + ( '%s_negative_remaining_window_' % rxDevName ) + \
         self.baseFilename + '.png'
      }
      return plotData

   def showUniqueSrcMacs( self ):
      uniqueSrcMacs = self.plugins[ 'EthernetPlugin' ].findUniqueSrcMacs()
      print( '\nUnique source MAC addresses and their associated IP addresses:' )
      for addr in sorted( uniqueSrcMacs.keys() ):
         print( '  %s (%s): %s' % ( addr, getCompanyName( addr ),
                                    sorted( uniqueSrcMacs[ addr ] ) ) )

   def showUniqueSrcIps( self, showMacAddrs=True, showCompanyNames=None ):
      if showCompanyNames is None:
         showCompanyNames = showMacAddrs
      assert showMacAddrs or not showCompanyNames, \
         'showCompanyNames cannot be True if showMacAddrs is False.'
      uniqueSrcIpsWithMacs = self.plugins[ 'IpPlugin' ].findUniqueSrcIpsWithMacs()
      print( '\nUnique source IP addresses%s:' % (
         ' and their associated MAC addresses' if showMacAddrs else '' ) )
      for ipAddr in sorted( uniqueSrcIpsWithMacs.keys() ):
         macAddrsStr = ''
         if showMacAddrs:
            macAddrs = uniqueSrcIpsWithMacs[ ipAddr ]
            macAddrStrs = []
            for mac in sorted( macAddrs ):
               name = ' (%s)' % getCompanyName( mac ) if showCompanyNames else ''
               macAddrStr = '%s%s' % ( mac, name )
               macAddrStrs.append( macAddrStr )
            macAddrsStr = ': ' + ', '.join( macAddrStrs )
         print( '  %s%s' % ( ipAddr, macAddrsStr ) )

   def analyzeWindowSize( self, frameNums, description, indent='  ' ):
      minWinSize = Min( 0xffffffff )
      maxWinSize = Max( 0 )
      frames = []
      for frameNum in frameNums:
         frame = self.frames[ frameNum ]
         frameTime = frame[ 'frame.time_relative' ]
         if self.stopAnalysisTime and frameTime > self.stopAnalysisTime:
            break
         frames.append( frame )
      winSize = np.empty( ( len( frames ) ), dtype=int )
      time = np.empty( ( len( frames ) ) )
      i = 0
      for frame in frames:
         size = frame[ 'tcp.window_size' ]
         minWinSize.maybeUpdate( size, frame[ 'frame.number' ] )
         maxWinSize.maybeUpdate( size, frame[ 'frame.number' ] )

         winSize[ i ] = size
         time[ i ] = frame[ 'frame.time_relative' ]
         i += 1
      print( '\n%s:' % ( description ) )
      minWinFrame = self.frames[ minWinSize.frameNum ]
      print( '%sMinimum window size %u at %.6f (frame %u)' % (
         indent, minWinSize.val, minWinFrame[ 'frame.time_relative' ],
         minWinSize.frameNum ) )
      maxWinFrame = self.frames[ maxWinSize.frameNum ]
      print( '%sMaximum window size %u at %.6f (frame %u)' % (
         indent, maxWinSize.val, maxWinFrame[ 'frame.time_relative' ],
         maxWinSize.frameNum ) )
      plotData = {
         'x': time,
         'y': winSize,
         'title': '%s (%s)' % ( description, self.pcapFilename ),
         'xlabel': 'Time (seconds)',
         'ylabel': 'TCP Window Size (bytes)'
      }
      return plotData

   def countFramesAndBytes( self, frameNums, description, indent='  ' ):
      lastFrameNum = frameNums[ 0 ]
      for frameNum in frameNums:
         frameTime = self.frames[ frameNum ][ 'frame.time_relative' ]
         if self.stopAnalysisTime and frameTime >= self.stopAnalysisTime:
            break
         lastFrameNum = frameNum
      lastFrameTime = self.frames[ lastFrameNum ][ 'frame.time_relative' ]
      # Add 1 microsecond so the last frame fits into the last time-slot (to avoid
      # "IndexError: index out of bounds").
      endOfLastTimeSlot = lastFrameTime + 0.000001
      timeSlotWidth = endOfLastTimeSlot / self.numTimeSlots
      print( '%s%s:' % ( indent, description ) )
      print( '%sendOfLastTimeSlot: %f, lastFrameTime: %f, timeSlotWidth: %f' % (
         indent * 2, endOfLastTimeSlot, lastFrameTime, timeSlotWidth ) )
      frameTimeSlots = np.zeros( self.numTimeSlots, dtype=int )
      tcpByteTimeSlots = np.zeros( self.numTimeSlots, dtype=int )
      updateTimeSlots = np.zeros( self.numTimeSlots, dtype=int )
      timeSlotIndices = np.empty( self.numTimeSlots, dtype=int )
      for i in range( self.numTimeSlots ):
         timeSlotIndices[ i ] = int( ( i + 1 ) * timeSlotWidth )
      for frameNum in frameNums:
         if frameNum > lastFrameNum:
            break
         frame = self.frames[ frameNum ]
         frameTime = frame[ 'frame.time_relative' ]
         i = int( frameTime / timeSlotWidth )
         frameTimeSlots[ i ] += 1
         tcpByteTimeSlots[ i ] += frame[ 'tcp.len' ]
         if 'bgp.type' in frame:
            updateTimeSlots[ i ] += frame[ 'bgp.type' ].count( updateStr )
      framesPerSecondTimeSlots = np.empty( self.numTimeSlots )
      tcpBytesPerSecondTimeSlots = np.empty( self.numTimeSlots )
      updatesPerSecondTimeSlots = np.empty( self.numTimeSlots )
      for i in range( self.numTimeSlots ):
         framesPerSecondTimeSlots[ i ] = frameTimeSlots[ i ] / timeSlotWidth
         tcpBytesPerSecondTimeSlots[ i ] = tcpByteTimeSlots[ i ] / timeSlotWidth
         updatesPerSecondTimeSlots[ i ] = updateTimeSlots[ i ] / timeSlotWidth

      plotData = {}
      plotData[ 'frame' ] = {
         'x': timeSlotIndices,
         'y': framesPerSecondTimeSlots,
         'title': '%s - frames per second (%s)' % ( description, self.pcapFilename ),
         'xlabel': 'Time (seconds)',
         'ylabel': 'Frames per second',
         'barwidth': timeSlotWidth
      }
      plotData[ 'byte' ] = {
         'x': timeSlotIndices,
         'y': tcpBytesPerSecondTimeSlots,
         'title': '%s - bytes per second (%s)' % ( description, self.pcapFilename ),
         'xlabel': 'Time (seconds)',
         'ylabel': 'TCP bytes per second',
         'barwidth': timeSlotWidth
      }
      plotData[ 'update' ] = {
         'x': timeSlotIndices,
         'y': updatesPerSecondTimeSlots,
         'title': '%s - Update msgs per second (%s)' % ( description,
                                                         self.pcapFilename ),
         'xlabel': 'Time (seconds)',
         'ylabel': 'Updates per second',
         'barwidth': timeSlotWidth
      }
      return plotData

   def analyzeDeltas( self, frameNums, description, indent='  ' ):
      # Ignore the first frame for updating the minimum - its delta is always zero.
      minDelta = Min( 1000000.0, ignoreFrames=[ 1 ] )
      maxDelta = Max( 0.0 )
      deltaSum = 0.0
      for frameNum in frameNums:
         frame = self.frames[ frameNum ]
         delta = frame[ 'frame.time_delta' ]
         deltaSum += delta
         minDelta.maybeUpdate( delta, frame[ 'frame.number' ] )
         maxDelta.maybeUpdate( delta, frame[ 'frame.number' ] )
      numFrames = len( frameNums )
      print( '%s%s:' % ( indent, description ) )
      print( '%sAverage frame time delta: %.6f (%u frames)' % (
         indent * 2, deltaSum / numFrames, numFrames ) )
      minDeltaFrame = self.frames[ minDelta.frameNum ]
      print( '%sMinimum delta %.6f at %.6f (frame %u)' % (
         indent * 2, minDelta.val, minDeltaFrame[ 'frame.time_relative' ],
         minDelta.frameNum ) )
      maxDeltaFrame = self.frames[ maxDelta.frameNum ]
      print( '%sMaximum delta %.6f at %.6f (frame %u)' % (
         indent * 2, maxDelta.val, maxDeltaFrame[ 'frame.time_relative' ],
         maxDelta.frameNum ) )

   # TODO: This function needs to filter frames to match specific values for _both_ source and destination.
   # TODO: It should be possible to filter based on any criteria, not just IP addresses.
   def doDeltaAnalysis( self, ip, devName ):
      print( '\n%s frame time deltas' % devName )
      allFramesForIp = self.plugins[ 'IpPlugin' ].framesPerIpSrc[ ip ]
      self.analyzeDeltas( allFramesForIp, 'All' )
      bgpFrames = [ f for f in allFramesForIp if 'bgp.type' in self.frames[ f ] ]
      self.analyzeDeltas( bgpFrames, 'BGP' )
      updateFrames = [ f for f in bgpFrames
                       if updateStr in self.frames[ f ][ 'bgp.type' ] ]
      self.analyzeDeltas( updateFrames, 'BGP Update' )
      tcpFrames = [ f for f in allFramesForIp if 'tcp.len' in self.frames[ f ] ]
      self.analyzeDeltas( tcpFrames, 'TCP ACK' )

   def doWindowSizeAnalysis( self, ip, devName ):
      plotData = self.analyzeWindowSize(
         self.plugins[ 'IpPlugin' ].framesPerIpSrc[ ip ],
         'All %s TCP Window Size' % devName )
      plotData[ 'imageName' ] = self.directory + ( '%s_winsize_' % devName ) + \
                                self.baseFilename + '.png'
      return plotData

   def doFrameAndByteCount( self, ip, devName ):
      print( '\nCounting frames, msgs & bytes' )
      plotData = self.countFramesAndBytes(
         self.plugins[ 'IpPlugin' ].framesPerIpSrc[ ip ], 'All %s frames' % devName )
      return plotData

   def doAnalysis( self, ip, devName ):
      print()
      self.plugins[ 'BgpPlugin' ].findEor( ip, devName )
      self.doDeltaAnalysis( ip, devName )
      winSizePlotData = self.doWindowSizeAnalysis( ip, devName )
      frameAndBytePlotData = self.doFrameAndByteCount( ip, devName )

      plotter = Plotter()
      plotter.plot( winSizePlotData, 'lines' )

      imageNameTemplate = self.directory + devName + '_%s_count_' + \
                          self.baseFilename + '.png'
      plotData = frameAndBytePlotData[ 'frame' ]
      plotData[ 'imageName' ] = imageNameTemplate % 'frame'
      plotter.plot( plotData, 'boxes' )

      plotData = frameAndBytePlotData[ 'byte' ]
      plotData[ 'imageName' ] = imageNameTemplate % 'byte'
      plotter.plot( plotData, 'boxes' )

      plotData = frameAndBytePlotData[ 'update' ]
      plotData[ 'imageName' ] = imageNameTemplate % 'update'
      plotter.plot( plotData, 'boxes' )

# TODO: Move to separate file.
#       Move getCompanyName function to generated file.
def buildOuiMap():
   # oui.tsv generated by:
   #  wget http://standards-oui.ieee.org/oui.txt
   #  grep "^..-..-.." oui.txt | sed s/"\s*(hex)\s*"/"\t"/g > oui.tsv
   import csv
   from pprint import pprint
   ouiMap = {}
   with open( 'oui.tsv', 'r' ) as tsvFile:
      ouiReader = csv.reader( tsvFile, delimiter='\t' )
      for line in ouiReader:
         oui, org = line
         oui = oui.replace( '-', ':' ).lower()
         ouiMap[ oui ] = org
      with open( 'OuiMap.py', 'w' ) as pyFile:
         print( '# Autogenerated by TODO\n\nouiMap = \\', file=pyFile )
         pprint( ouiMap, pyFile )

def debugPrintFrames( frames, description ):
   print( '\n\nNum %s: %u' % ( description, len( frames ) ) )
   for number in sorted( frames.keys() ):
      pprint( frames[ number ], indent=4 )

def getCompanyName( addr ):
   return ouiMap.get( addr[ 0:8 ].lower(), 'Unknown' )

def filterTcpFrame( ipA, ipB, frame ):
   if 'IP_SRC' not in frame or 'IP_DST' not in frame:
      return False
   addrs = [ ipA, ipB ]
   if frame[ 'IP_SRC' ] not in addrs or frame[ 'IP_DST' ] not in addrs:
      return False
   if frame[ 'IP_SRC' ] == frame[ 'IP_DST' ]:
      return False
   if 'tcp.len' not in frame:
      return False
   return True

# filterFunc = lambda frame: filterTcpFrame( ipA, ipB, frame )
   
def srcIpArg( s ):
   '''Process a command-line IP address (and optional device name).'''
   try:
      args = s.split( '/' )
      count = len( args )
      if count < 1 or count > 2:
         raise
      # Could validate the IP address, but won't for now...
      ipAddr = args[ 0 ]
      if count == 1:
         # devName not supplied, so use ipAddr as devName.
         return ipAddr, ipAddr
      else:
         devName = args[ 1 ]
         return ipAddr, devName
   except:
      raise argparse.ArgumentTypeError(
         'Source IP must be a valid IP address, optionally followed (separated'
         ' with a forward-slash) by a device name.' )

if __name__ == "__main__":
   from os.path import basename
   arg_parser = argparse.ArgumentParser(
      description='Analyze a .pcap file. Sample usage:\n'
      '  %s SlowBgpUpdates.pcap --src-ip 10.0.0.101/Arista'
      ' --src-ip 10.0.0.100/Peer' %
      basename( __file__ ), formatter_class=argparse.RawTextHelpFormatter )
   arg_parser.add_argument(
      'filename', help='Name of file (with .pcap extension) to analyze' )
   arg_parser.add_argument(
      '--src-ip', type=srcIpArg, action='append',
      metavar=( 'SRC_IP or SRC_IP/DEV_NAME' ),
      help='Source IP address of a device, optionally separated from a device name\n'
           'by a forward-slash, to analyze. If supplied, the device name is used\n'
           'instead of the IP address in output, filenames, etc.\n'
           'More than one address can be supplied.' )
   arg_parser.add_argument(
      '-n', '--num-time-slots', type=int, default=80,
      help='Number of time slots to use for counting frames, messages or bytes' )
   arg_parser.add_argument(
      '--keep-json', action='store_true', help='For debug, keep interim JSON file' )
   args = arg_parser.parse_args()

   pcapInspect = PcapInspect( args.filename, numTimeSlots=args.num_time_slots,
                              stopAnalysisTime=300, keepJson=args.keep_json )

   pcapInspect.showUniqueSrcMacs()
   pcapInspect.showUniqueSrcIps()
   pcapInspect.showUniqueSrcIps( showMacAddrs=False )
   pcapInspect.showUniqueSrcIps( showCompanyNames=False )
   pcapInspect.showUniqueSrcIps( showMacAddrs=False, showCompanyNames=False )
   try:
      pcapInspect.showUniqueSrcIps( showMacAddrs=False, showCompanyNames=True )
      functionHasAsserted = False
   except:
      functionHasAsserted = True
   assert functionHasAsserted, \
      "Assertion 'failure' expected in showUniqueSrcIps, but didn't happen."

   for ipAddr, devName in args.src_ip:
      pcapInspect.doAnalysis( ipAddr, devName )
